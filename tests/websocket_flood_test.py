#!/usr/bin/env python3
"""
WebSocket Flood Test
Opens many concurrent WebSocket connections and/or sends high-frequency frames
to test server support for real-time protocols. Checks for connection limits,
frame-dropping, and application-level backpressure handling.
"""

import asyncio
import argparse
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import websockets
    from websockets.exceptions import ConnectionClosed
except ImportError:
    websockets = None
    ConnectionClosed = None


async def websocket_worker(uri, worker_id, frame_count, frame_delay, results):
    """
    Worker coroutine that opens a WebSocket connection and sends/receives frames.
    
    Args:
        uri: WebSocket URI (e.g., wss://yourdomain.com/ws)
        worker_id: Worker identifier
        frame_count: Number of frames to send per connection
        frame_delay: Delay in seconds between frames
        results: Shared dict to collect metrics
    """
    try:
        async with websockets.connect(uri, ping_interval=None) as websocket:
            results['connections_established'] += 1
            
            for frame_idx in range(frame_count):
                try:
                    # Send a test message
                    test_message = f"worker_{worker_id}_frame_{frame_idx}"
                    start_time = time.time()
                    
                    await websocket.send(test_message)
                    results['frames_sent'] += 1
                    
                    # Try to receive response (with timeout)
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=5)
                        elapsed = time.time() - start_time
                        results['frames_received'] += 1
                        results['latencies'].append(elapsed)
                    except asyncio.TimeoutError:
                        results['receive_timeouts'] += 1
                    
                    # Delay before next frame
                    await asyncio.sleep(frame_delay)
                
                except ConnectionClosed:
                    results['connection_closed_during_send'] += 1
                    break
                except Exception as e:
                    results['send_errors'] += 1
                    break
    
    except asyncio.TimeoutError:
        results['connection_timeouts'] += 1
    except ConnectionRefusedError:
        results['connection_refused'] += 1
    except OSError as e:
        if "Too many open files" in str(e):
            results['file_descriptor_limit'] += 1
        else:
            results['connection_errors'] += 1
    except Exception as e:
        results['connection_errors'] += 1


async def run_test(url, ws_path, concurrency, duration, frame_delay):
    """
    Main test orchestrator: open concurrent WebSocket connections.
    
    Args:
        url: Target URL (e.g., https://yourdomain.com or wss://yourdomain.com)
        ws_path: WebSocket path (e.g., '/ws', '/socket.io')
        concurrency: Number of concurrent connections
        duration: Test duration in seconds
        frame_delay: Delay between frames in seconds
    """
    # Parse and convert URL to WebSocket scheme
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc.split(':')[0]
    port = parsed.port or (443 if parsed.scheme in ['https', 'wss'] else 80)
    scheme = 'wss' if parsed.scheme in ['https', 'wss'] else 'ws'
    
    ws_uri = f"{scheme}://{host}:{port}{ws_path}"
    
    results = {
        'connections_established': 0,
        'connection_timeouts': 0,
        'connection_refused': 0,
        'connection_errors': 0,
        'connection_closed_during_send': 0,
        'file_descriptor_limit': 0,
        'frames_sent': 0,
        'frames_received': 0,
        'send_errors': 0,
        'receive_timeouts': 0,
        'latencies': [],
    }
    
    print(f"\n[*] Starting WebSocket Flood Test")
    print(f"    Target: {ws_uri}")
    print(f"    Concurrency: {concurrency}")
    print(f"    Duration: {duration}s")
    print(f"    Frame Delay: {frame_delay}s")
    print(f"    Test Start Time: {datetime.now().isoformat()}\n")
    
    start_time = time.time()
    
    # Calculate frames per worker based on duration
    frames_per_worker = max(1, int(duration / frame_delay) + 1) if frame_delay > 0 else 1
    
    # Create and run workers
    tasks = [
        websocket_worker(ws_uri, i, frames_per_worker, frame_delay, results)
        for i in range(concurrency)
    ]
    
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration + 10)
    except asyncio.TimeoutError:
        pass
    
    elapsed = time.time() - start_time
    
    # Generate summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Elapsed Time: {elapsed:.2f}s")
    print(f"Expected Connections: {concurrency}")
    print(f"Established Connections: {results['connections_established']}")
    print(f"Connection Success Rate: {(results['connections_established'] / concurrency * 100):.1f}%")
    
    print(f"\nConnection Errors:")
    print(f"  Timeouts: {results['connection_timeouts']}")
    print(f"  Refused: {results['connection_refused']}")
    print(f"  Other Errors: {results['connection_errors']}")
    print(f"  File Descriptor Limit: {results['file_descriptor_limit']}")
    
    print(f"\nFrame Statistics:")
    print(f"  Frames Sent: {results['frames_sent']}")
    print(f"  Frames Received: {results['frames_received']}")
    print(f"  Send Errors: {results['send_errors']}")
    print(f"  Receive Timeouts: {results['receive_timeouts']}")
    print(f"  Connections Closed During Send: {results['connection_closed_during_send']}")
    
    if results['latencies']:
        latencies = sorted(results['latencies'])
        print(f"\nLatency Statistics:")
        print(f"  Min: {min(latencies):.3f}s")
        print(f"  Max: {max(latencies):.3f}s")
        print(f"  Avg: {sum(latencies) / len(latencies):.3f}s")
        print(f"  Median: {latencies[len(latencies)//2]:.3f}s")
    
    # Protection verdict
    print("\n" + "="*70)
    print("PROTECTION ANALYSIS")
    print("="*70)
    
    connection_limit_hit = (
        results['file_descriptor_limit'] > 0 or
        results['connections_established'] < concurrency * 0.8
    )
    frames_dropped = (
        results['frames_sent'] > results['frames_received'] * 1.5
    )
    backpressure_detected = (
        results['receive_timeouts'] > 0 or
        results['connection_closed_during_send'] > 0
    )
    
    if connection_limit_hit or frames_dropped or backpressure_detected:
        print("\n✓ Server Shows WebSocket Resource Limits:")
        if connection_limit_hit:
            print(f"  - Connection limits enforced ({results['connections_established']}/{concurrency})")
        if frames_dropped:
            print(f"  - Frame dropping or throttling detected")
        if backpressure_detected:
            print(f"  - Backpressure or connection closure on overload")
        print("\n  Verdict: Server has some protection against WebSocket floods.")
    else:
        print("\n✗ Limited WebSocket protections detected:")
        print(f"  - All {results['connections_established']} connections accepted")
        print(f"  - Frames not dropped ({results['frames_sent']} sent, {results['frames_received']} received)")
        print(f"  - No obvious backpressure")
        print("\n  Verdict: Consider adding connection limits, frame rate limiting, and memory caps.")


def websocket_flood_test():
    if websockets is None:
        print("Error: 'websockets' package not installed.")
        print("Install it with: pip install websockets")
        return
    
    parser = argparse.ArgumentParser(
        description="Test WebSocket server resilience under connection/frame flooding"
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g., https://yourdomain.com or wss://yourdomain.com)"
    )
    parser.add_argument(
        "--ws-path",
        default="/ws",
        help="WebSocket path (e.g., '/ws', '/socket.io')"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=50,
        help="Number of concurrent WebSocket connections"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Test duration in seconds"
    )
    parser.add_argument(
        "--frame-delay",
        type=float,
        default=0.5,
        help="Delay in seconds between frames per connection"
    )
    
    args = parser.parse_args()
    
    asyncio.run(run_test(
        args.url,
        args.ws_path,
        args.concurrency,
        args.duration,
        args.frame_delay
    ))


if __name__ == "__main__":
    websocket_flood_test()
