// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scan

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// ConcurrentConfig расширяет базовую Config с параметрами конкурентности
type ConcurrentConfig struct {
	*Config
	Workers        int           // Количество рабочих потоков
	Services       []string      // Фильтр по сервисам (если пусто - все)
	MaxConnections int           // Максимум одновременных соединений
}

// ScanTargetsConcurrent сканирует цели с поддержкой конкурентности и фильтрации по сервисам
func (c *ConcurrentConfig) ScanTargetsConcurrent(targets []plugins.Target) ([]*plugins.Service, error) {
	if c.Workers <= 0 {
		c.Workers = 10
	}

	// Канал для распределения задач
	taskChan := make(chan plugins.Target, c.Workers*2)
	resultChan := make(chan *plugins.Service, len(targets))
	errChan := make(chan error, len(targets))

	var wg sync.WaitGroup

	// Запуск worker горутин
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go c.scanWorker(&wg, taskChan, resultChan, errChan)
	}

	// Отправка задач в канал
	go func() {
		for _, target := range targets {
			taskChan <- target
		}
		close(taskChan)
	}()

	// Ожидание завершения всех воркеров
	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	var results []*plugins.Service
	for result := range resultChan {
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// scanWorker обрабатывает целевые хосты без блокировки
func (c *ConcurrentConfig) scanWorker(wg *sync.WaitGroup, taskChan <-chan plugins.Target, resultChan chan<- *plugins.Service, errChan chan<- error) {
	defer wg.Done()

	for target := range taskChan {
		// Каждая задача имеет собственный timeout контекст
		ctx, cancel := context.WithTimeout(context.Background(), c.Config.DefaultTimeout)

		// Результат в отдельной горутине, чтобы не блокировать worker
		go func(t plugins.Target, ctx context.Context) {
			result := c.scanTargetWithContext(t, ctx)
			if result != nil {
				resultChan <- result
			}
		}(target, ctx)

		// Не ждем завершения, переходим к следующей задаче
		cancel() // Отменим в конце обработки
	}
}

// scanTargetWithContext сканирует один таргет с контекстом
func (c *ConcurrentConfig) scanTargetWithContext(target plugins.Target, ctx context.Context) *plugins.Service {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	// Если есть фильтр сервисов, используем только их
	if len(c.Services) > 0 {
		return c.scanTargetFilteredServices(target, ctx)
	}

	// Иначе используем стандартное сканирование как в fast mode
	result, err := c.scanTargetConcurrent(target, ctx)
	if err != nil && c.Config.Verbose {
		log.Printf("error: %v scanning %v\n", err, target.Address.String())
	}
	return result
}

// scanTargetFilteredServices сканирует только выбранные сервисы
func (c *ConcurrentConfig) scanTargetFilteredServices(target plugins.Target, ctx context.Context) *plugins.Service {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	// Создаем map выбранных сервисов для быстрого поиска
	selectedServices := make(map[string]bool)
	for _, svc := range c.Services {
		selectedServices[svc] = true
	}

	// Сканируем TCP плагины
	for _, plugin := range sortedTCPPlugins {
		pluginID := plugins.CreatePluginID(plugin)
		if !selectedServices[pluginID] {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := DialTCP(ip, port)
		if err != nil {
			if c.Config.Verbose {
				log.Printf("unable to connect to %s:%d for %s: %v\n", ip, port, pluginID, err)
			}
			continue
		}

		result, err := simplePluginRunner(conn, target, c.Config, plugin)
		if result != nil && err == nil {
			conn.Close()
			return result
		}
		conn.Close()
	}

	// Пробуем TLS плагины
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	tlsConn, tlsErr := DialTLS(target)
	if tlsErr == nil {
		defer tlsConn.Close()

		for _, plugin := range sortedTCPTLSPlugins {
			pluginID := plugins.CreatePluginID(plugin)
			if !selectedServices[pluginID] {
				continue
			}

			select {
			case <-ctx.Done():
				return nil
			default:
			}

			result, err := simplePluginRunner(tlsConn, target, c.Config, plugin)
			if result != nil && err == nil {
				return result
			}

			// Переоткрываем TLS соединение для следующего плагина
			tlsConn, err = DialTLS(target)
			if err != nil {
				if c.Config.Verbose {
					log.Printf("error reconnecting via TLS to %s: %v\n", target.Address.String(), err)
				}
				break
			}
		}
	}

	// UDP плагины если включены
	if c.Config.UDP {
		for _, plugin := range sortedUDPPlugins {
			pluginID := plugins.CreatePluginID(plugin)
			if !selectedServices[pluginID] {
				continue
			}

			select {
			case <-ctx.Done():
				return nil
			default:
			}

			conn, err := DialUDP(ip, port)
			if err != nil {
				if c.Config.Verbose {
					log.Printf("unable to connect UDP to %s:%d: %v\n", ip, port, err)
				}
				continue
			}

			result, err := simplePluginRunner(conn, target, c.Config, plugin)
			if result != nil && err == nil {
				conn.Close()
				return result
			}
			conn.Close()
		}
	}

	return nil
}

// scanTargetConcurrent - быстрое сканирование с поддержкой контекста
func (c *ConcurrentConfig) scanTargetConcurrent(target plugins.Target, ctx context.Context) (*plugins.Service, error) {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	// TCP плагины с приоритетом портов
	for _, plugin := range sortedTCPPlugins {
		if !plugin.PortPriority(port) {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout scanning TCP plugins")
		default:
		}

		conn, err := DialTCP(ip, port)
		if err != nil {
			continue
		}

		result, err := simplePluginRunner(conn, target, c.Config, plugin)
		conn.Close()
		if result != nil && err == nil {
			return result, nil
		}
	}

	// TLS плагины с приоритетом портов
	tlsConn, tlsErr := DialTLS(target)
	if tlsErr == nil {
		defer tlsConn.Close()

		for _, plugin := range sortedTCPTLSPlugins {
			if !plugin.PortPriority(port) {
				continue
			}

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("timeout scanning TLS plugins")
			default:
			}

			result, err := simplePluginRunner(tlsConn, target, c.Config, plugin)
			if result != nil && err == nil {
				return result, nil
			}

			tlsConn, err = DialTLS(target)
			if err != nil {
				break
			}
		}
	}

	// Если fastMode - выходим
	if c.Config.FastMode {
		return nil, nil
	}

	// UDP сканирование если включено
	if c.Config.UDP {
		for _, plugin := range sortedUDPPlugins {
			if !plugin.PortPriority(port) {
				continue
			}

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("timeout scanning UDP plugins")
			default:
			}

			conn, err := DialUDP(ip, port)
			if err != nil {
				continue
			}

			result, err := simplePluginRunner(conn, target, c.Config, plugin)
			conn.Close()
			if result != nil && err == nil {
				return result, nil
			}
		}
	}

	return nil, nil
}

// FilterServicesByName фильтрует доступные сервисы по названиям
func FilterServicesByName(serviceNames []string) []string {
	if len(serviceNames) == 0 {
		return []string{}
	}

	// Создаем set выбранных сервисов
	selected := make(map[string]bool)
	for _, name := range serviceNames {
		selected[name] = true
	}

	var result []string

	// Фильтруем TCP плагины
	for _, plugin := range sortedTCPPlugins {
		id := plugins.CreatePluginID(plugin)
		if selected[id] {
			result = append(result, id)
		}
	}

	// Фильтруем TLS плагины
	for _, plugin := range sortedTCPTLSPlugins {
		id := plugins.CreatePluginID(plugin)
		if selected[id] {
			result = append(result, id)
		}
	}

	// Фильтруем UDP плагины
	for _, plugin := range sortedUDPPlugins {
		id := plugins.CreatePluginID(plugin)
		if selected[id] {
			result = append(result, id)
		}
	}

	return result
}

// GetAvailableServices возвращает все доступные сервисы
func GetAvailableServices() []string {
	var services []string

	for _, plugin := range sortedTCPPlugins {
		services = append(services, plugins.CreatePluginID(plugin))
	}

	for _, plugin := range sortedTCPTLSPlugins {
		services = append(services, plugins.CreatePluginID(plugin))
	}

	for _, plugin := range sortedUDPPlugins {
		services = append(services, plugins.CreatePluginID(plugin))
	}

	return services
}
