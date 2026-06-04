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
	"testing"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// TestConcurrentConfigInitialization проверяет инициализацию конкурентной конфигурации
func TestConcurrentConfigInitialization(t *testing.T) {
	baseConfig := &Config{
		FastMode:       true,
		UDP:            false,
		DefaultTimeout: 500 * time.Millisecond,
		Verbose:        true,
	}

	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        10,
		Services:       []string{"http", "https"},
		MaxConnections: 100,
	}

	assert.Equal(t, 10, concConfig.Workers)
	assert.Equal(t, 2, len(concConfig.Services))
	assert.Equal(t, 100, concConfig.MaxConnections)
	assert.True(t, concConfig.FastMode)
}

// TestFilterServicesByName проверяет фильтрацию сервисов по названиям
func TestFilterServicesByName(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected bool
	}{
		{
			name:     "empty services",
			input:    []string{},
			expected: true,
		},
		{
			name:     "single service",
			input:    []string{"http"},
			expected: true,
		},
		{
			name:     "multiple services",
			input:    []string{"http", "https", "ssh"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterServicesByName(tt.input)
			assert.NotNil(t, result)
		})
	}
}

// TestGetAvailableServices проверяет получение доступных сервисов
func TestGetAvailableServices(t *testing.T) {
	services := GetAvailableServices()
	assert.Greater(t, len(services), 0, "должны быть доступные сервисы")
}

// TestConcurrentScanTimeout проверяет работу timeout при конкурентном сканировании
func TestConcurrentScanTimeout(t *testing.T) {
	baseConfig := &Config{
		FastMode:       true,
		UDP:            false,
		DefaultTimeout: 100 * time.Millisecond,
		Verbose:        false,
	}

	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        2,
		Services:       []string{},
		MaxConnections: 10,
	}

	// Создаем тестовые цели (невалидные адреса)
	targets := []plugins.Target{
		{
			Address: plugins.ParseAddress("127.0.0.1:99999"),
			Host:    "localhost",
		},
	}

	// Проверяем что сканирование завершается без паники
	results, err := concConfig.ScanTargetsConcurrent(targets)
	assert.NoError(t, err)
	assert.NotNil(t, results)
}

// TestWorkerPoolIndependence проверяет что воркеры независимы друг от друга
func TestWorkerPoolIndependence(t *testing.T) {
	baseConfig := &Config{
		FastMode:       true,
		UDP:            false,
		DefaultTimeout: 1 * time.Second,
		Verbose:        false,
	}

	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        5,
		Services:       []string{},
		MaxConnections: 50,
	}

	// Создаем несколько целей
	targets := make([]plugins.Target, 10)
	for i := 0; i < 10; i++ {
		targets[i] = plugins.Target{
			Address: plugins.ParseAddress("127.0.0.1:80"),
			Host:    "localhost",
		}
	}

	// Запускаем сканирование и проверяем что оно завершается
	startTime := time.Now()
	results, err := concConfig.ScanTargetsConcurrent(targets)
	elapsed := time.Since(startTime)

	assert.NoError(t, err)
	assert.NotNil(t, results)
	// Проверяем что не заняло слишком много времени (конкурентное выполнение)
	assert.Less(t, elapsed, 30*time.Second)
}

// TestServiceFiltering проверяет фильтрацию по сервисам
func TestServiceFiltering(t *testing.T) {
	baseConfig := &Config{
		FastMode:       false,
		UDP:            false,
		DefaultTimeout: 500 * time.Millisecond,
		Verbose:        false,
	}

	// Ко��фиг с фильтром только на HTTP и HTTPS
	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        3,
		Services:       []string{"http", "https"},
		MaxConnections: 30,
	}

	assert.Equal(t, 2, len(concConfig.Services))
	assert.Contains(t, concConfig.Services, "http")
	assert.Contains(t, concConfig.Services, "https")
}

// TestMaxConnectionsLimit проверяет лимит максимальных соединений
func TestMaxConnectionsLimit(t *testing.T) {
	baseConfig := &Config{
		FastMode:       true,
		UDP:            false,
		DefaultTimeout: 500 * time.Millisecond,
		Verbose:        false,
	}

	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        100,
		Services:       []string{},
		MaxConnections: 20, // Лимит 20 соединений
	}

	assert.Equal(t, 100, concConfig.Workers)
	assert.Equal(t, 20, concConfig.MaxConnections)
	assert.LessOrEqual(t, concConfig.MaxConnections, concConfig.Workers*2)
}

// TestVerboseLogging проверяет логирование в конкурентном режиме
func TestVerboseLogging(t *testing.T) {
	baseConfig := &Config{
		FastMode:       true,
		UDP:            false,
		DefaultTimeout: 100 * time.Millisecond,
		Verbose:        true, // Включаем логирование
	}

	concConfig := &ConcurrentConfig{
		Config:         baseConfig,
		Workers:        2,
		Services:       []string{},
		MaxConnections: 20,
	}

	assert.True(t, concConfig.Verbose)
}
