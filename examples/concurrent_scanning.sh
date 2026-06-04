#!/bin/bash
# Examples of using fingerprintx with concurrent scanning and streaming

echo "Example 1: Basic concurrent scanning with service filter"
echo "Command: ./fingerprintx -t 192.168.1.1:443 -m http,https -json"
echo "Description: Scans one target, checks ONLY http and https services, outputs JSON"
echo ""

echo "Example 2: Stream large file with 20 workers"
echo "Command: ./fingerprintx -l targets.txt -workers 20 -buffer-size 524288"
echo "Description: Streams targets from file, 20 workers, 512KB buffer"
echo ""

echo "Example 3: Filter specific services without blocking"
echo "Command: ./fingerprintx -l large_targets.txt -m ssh,rdp,mysql -workers 50 -timeout 500"
echo "Description: Only SSH, RDP, MySQL; 50 workers; timeout 500ms per target"
echo ""

echo "Example 4: Fast mode with concurrent workers"
echo "Command: ./fingerprintx -l targets.txt -fast -workers 100 -m http,https"
echo "Description: Fast mode only checks default port services, 100 workers"
echo ""

echo "Example 5: Stream from stdin with service filter"
echo "Command: cat targets.txt | ./fingerprintx -m ssh,rdp -workers 25 -json -o results.json"
echo "Description: Read from stdin, filter services, output to file"
echo ""

echo "Example 6: Small buffer for low memory environments"
echo "Command: ./fingerprintx -l targets.txt -workers 10 -buffer-size 65536"
echo "Description: 64KB buffer, ideal for limited resources"
echo ""

echo "Example 7: Large buffer for massive target lists"
echo "Command: ./fingerprintx -l huge_targets.txt -workers 50 -buffer-size 1048576"
echo "Description: 1MB buffer, best for 100K+ targets"
echo ""

echo "Example 8: Complete configuration example"
echo "Command: ./fingerprintx \\"
echo "  -l targets.txt \\"
echo "  -m http,https,ssh,mysql,postgresql \\"
echo "  -workers 30 \\"
echo "  -buffer-size 262144 \\"
echo "  -timeout 1000 \\"
echo "  -fast=false \\"
echo "  -json \\"
echo "  -o results.json \\"
echo "  -verbose"
echo "Description: Full control over all scanning parameters"
echo ""

echo "Example 9: List available services"
echo "Command: ./fingerprintx -services-list"
echo "Description: Shows all available services for filtering"
echo ""

echo "Example 10: Connection limiting"
echo "Command: ./fingerprintx -l targets.txt -workers 20 -max-connections 100"
echo "Description: Max 100 simultaneous connections, 20 workers"
echo ""
