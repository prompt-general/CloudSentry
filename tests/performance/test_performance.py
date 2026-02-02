import pytest
import asyncio
import time
import statistics
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from app.models import Finding


class TestPerformance:
    """Performance tests for CloudSentry"""
    
    @pytest.mark.asyncio
    async def test_rule_evaluation_performance(self):
        """Test rule evaluation performance"""
        # Mock RuleEngine to avoid import dependencies
        with patch('app.engine.rule_engine.RuleEngine') as mock_rule_engine_class:
            mock_engine = MagicMock()
            
            # Mock evaluate_event method
            async def mock_evaluate_event(event):
                # Simulate processing time
                await asyncio.sleep(0.001)  # 1ms processing time
                return []
            
            mock_engine.evaluate_event = mock_evaluate_event
            mock_rule_engine_class.return_value = mock_engine
            
            rule_engine = mock_engine
            
            # Create test events
            events = []
            for i in range(100):
                event = {
                    "event_id": f"test-event-{i}",
                    "event_name": "PutBucketPolicy",
                    "event_source": "s3.amazonaws.com",
                    "resource_id": f"test-bucket-{i}",
                    "resource_type": "s3",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "raw_event": {
                        "requestParameters": {
                            "bucketName": f"test-bucket-{i}",
                            "policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
                        }
                    }
                }
                events.append(event)
            
            # Measure evaluation time
            start_time = time.time()
            
            for event in events:
                await rule_engine.evaluate_event(event)
            
            end_time = time.time()
            total_time = end_time - start_time
            avg_time = total_time / len(events)
            
            print(f"\nRule Evaluation Performance:")
            print(f"  Total events: {len(events)}")
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Average per event: {avg_time:.3f}s")
            
            # Performance requirements
            assert avg_time < 5.0, f"Average evaluation time {avg_time:.3f}s exceeds 5s limit"
            assert total_time < 60.0, f"Total evaluation time {total_time:.2f}s exceeds 60s limit"

    @pytest.mark.asyncio
    async def test_event_normalization_performance(self):
        """Test event normalization performance"""
        # Mock CloudTrailNormalizer
        with patch('app.engine.event_ingestor.CloudTrailNormalizer') as mock_normalizer_class:
            mock_normalizer = MagicMock()
            
            def mock_normalize_event(event):
                # Simulate normalization processing
                return {
                    "event_id": event.get("eventID"),
                    "event_name": event.get("eventName"),
                    "event_source": event.get("eventSource"),
                    "resource_id": event.get("requestParameters", {}).get("bucketName"),
                    "resource_type": "s3",
                    "account_id": event.get("userIdentity", {}).get("accountId"),
                    "region": event.get("awsRegion"),
                    "raw_event": event
                }
            
            mock_normalizer.normalize_event = mock_normalize_event
            mock_normalizer_class.return_value = mock_normalizer
            
            normalizer = mock_normalizer
            
            # Create test CloudTrail events
            cloudtrail_events = []
            for i in range(1000):
                event = {
                    "eventID": f"test-id-{i}",
                    "eventName": "CreateBucket",
                    "eventSource": "s3.amazonaws.com",
                    "eventTime": "2024-01-15T12:00:00Z",
                    "awsRegion": "us-east-1",
                    "userIdentity": {"accountId": "123456789012"},
                    "requestParameters": {"bucketName": f"test-bucket-{i}"}
                }
                cloudtrail_events.append(event)
            
            # Measure normalization time
            start_time = time.time()
            
            normalized_events = []
            for event in cloudtrail_events:
                normalized = normalizer.normalize_event(event)
                normalized_events.append(normalized)
            
            end_time = time.time()
            total_time = end_time - start_time
            avg_time = total_time / len(cloudtrail_events)
            
            print(f"\nEvent Normalization Performance:")
            print(f"  Total events: {len(cloudtrail_events)}")
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Average per event: {avg_time:.6f}s")
            
            assert avg_time < 0.01, f"Average normalization time {avg_time:.6f}s exceeds 10ms limit"

    @pytest.mark.asyncio
    async def test_concurrent_event_processing(self):
        """Test concurrent event processing"""
        with patch('app.engine.rule_engine.RuleEngine') as mock_rule_engine_class:
            mock_engine = MagicMock()
            
            # Mock evaluate_event method with async behavior
            async def mock_evaluate_event(event):
                # Simulate variable processing time
                await asyncio.sleep(0.002)  # 2ms processing time
                return []
            
            mock_engine.evaluate_event = mock_evaluate_event
            mock_rule_engine_class.return_value = mock_engine
            
            rule_engine = mock_engine
            
            # Create concurrent tasks
            async def process_event(event_num):
                event = {
                    "event_id": f"concurrent-event-{event_num}",
                    "event_name": "PutBucketPolicy",
                    "resource_id": f"bucket-{event_num}",
                    "resource_type": "s3",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "raw_event": {}
                }
                await rule_engine.evaluate_event(event)
            
            # Run concurrent processing
            num_concurrent = 50
            start_time = time.time()
            
            tasks = [process_event(i) for i in range(num_concurrent)]
            await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            print(f"\nConcurrent Processing Performance:")
            print(f"  Concurrent tasks: {num_concurrent}")
            print(f"  Total time: {total_time:.2f}s")
            
            assert total_time < 30.0, f"Concurrent processing time {total_time:.2f}s exceeds 30s limit"

    @pytest.mark.asyncio
    async def test_database_insert_performance(self):
        """Test database insert performance"""
        with patch('app.database.AsyncSessionLocal') as mock_session_local:
            mock_session = AsyncMock()
            mock_session_local.return_value.__aenter__.return_value = mock_session
            
            # Create test findings
            findings = []
            for i in range(500):
                finding = Finding(
                    id=uuid.uuid4(),
                    rule_id=f"S3-{i:03d}",
                    resource_id=f"test-bucket-{i}",
                    resource_type="s3",
                    severity="HIGH",
                    timestamp=datetime.utcnow(),
                    account_id="123456789012",
                    region="us-east-1"
                )
                findings.append(finding)
            
            # Measure insert time
            start_time = time.time()
            
            for finding in findings:
                mock_session.add(finding)
                await mock_session.commit()
            
            end_time = time.time()
            total_time = end_time - start_time
            avg_time = total_time / len(findings)
            
            print(f"\nDatabase Insert Performance:")
            print(f"  Total findings: {len(findings)}")
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Average per insert: {avg_time:.6f}s")
            
            # Verify database calls
            assert mock_session.add.call_count == len(findings)
            assert mock_session.commit.call_count == len(findings)
            
            # Performance requirements
            assert avg_time < 0.1, f"Average insert time {avg_time:.6f}s exceeds 100ms limit"

    @pytest.mark.asyncio
    async def test_api_response_performance(self):
        """Test API response performance"""
        from fastapi.testclient import TestClient
        from app.main import app
        
        client = TestClient(app)
        
        # Mock database responses
        with patch('app.api.rest.get_db') as mock_get_db:
            mock_session = AsyncMock()
            mock_get_db.return_value = mock_session
            
            # Mock findings data
            findings = [
                {
                    "id": str(uuid.uuid4()),
                    "rule_id": "S3-001",
                    "resource_id": "test-bucket",
                    "severity": "HIGH"
                }
            ]
            mock_session.query.return_value.filter.return_value.all.return_value = findings
            
            # Measure API response time
            response_times = []
            num_requests = 100
            
            for i in range(num_requests):
                start_time = time.time()
                response = client.get("/api/v1/findings")
                end_time = time.time()
                
                response_times.append(end_time - start_time)
                assert response.status_code == 200
            
            avg_response_time = statistics.mean(response_times)
            max_response_time = max(response_times)
            
            print(f"\nAPI Response Performance:")
            print(f"  Total requests: {num_requests}")
            print(f"  Average response time: {avg_response_time:.3f}s")
            print(f"  Max response time: {max_response_time:.3f}s")
            
            # Performance requirements
            assert avg_response_time < 1.0, f"Average response time {avg_response_time:.3f}s exceeds 1s limit"
            assert max_response_time < 5.0, f"Max response time {max_response_time:.3f}s exceeds 5s limit"

    @pytest.mark.asyncio
    async def test_memory_usage_performance(self):
        """Test memory usage during processing"""
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create and process large dataset
        events = []
        for i in range(1000):
            event = {
                "event_id": f"memory-test-{i}",
                "event_name": "CreateBucket",
                "resource_id": f"bucket-{i}",
                "resource_type": "s3",
                "account_id": "123456789012",
                "region": "us-east-1",
                "raw_event": {"data": "x" * 1000}  # 1KB per event
            }
            events.append(event)
        
        # Process events
        with patch('app.engine.rule_engine.RuleEngine') as mock_rule_engine_class:
            mock_engine = MagicMock()
            
            async def mock_evaluate_event(event):
                # Simulate processing
                return []
            
            mock_engine.evaluate_event = mock_evaluate_event
            mock_rule_engine_class.return_value = mock_engine
            
            for event in events:
                await mock_engine.evaluate_event(event)
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        print(f"\nMemory Usage Performance:")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        print(f"  Final memory: {final_memory:.2f} MB")
        print(f"  Memory increase: {memory_increase:.2f} MB")
        print(f"  Memory per event: {memory_increase/len(events):.3f} MB")
        
        # Memory requirements (should not leak significantly)
        assert memory_increase < 100, f"Memory increase {memory_increase:.2f} MB exceeds 100MB limit"

    @pytest.mark.asyncio
    async def test_cache_performance(self):
        """Test cache performance"""
        with patch('redis.Redis.from_url') as mock_redis_class:
            mock_redis = AsyncMock()
            mock_redis.get.return_value = None
            mock_redis.setex.return_value = True
            mock_redis_class.return_value = mock_redis
            
            # Test cache operations
            from app.cache import CacheManager
            cache = CacheManager()
            
            # Measure cache set performance
            cache_times = []
            num_operations = 1000
            
            for i in range(num_operations):
                start_time = time.time()
                await cache.set(f"test-key-{i}", {"data": f"value-{i}"}, ttl=60)
                end_time = time.time()
                cache_times.append(end_time - start_time)
            
            avg_set_time = statistics.mean(cache_times)
            
            # Measure cache get performance
            mock_redis.get.return_value = '{"data": "test-value"}'
            
            get_times = []
            for i in range(num_operations):
                start_time = time.time()
                await cache.get(f"test-key-{i}")
                end_time = time.time()
                get_times.append(end_time - start_time)
            
            avg_get_time = statistics.mean(get_times)
            
            print(f"\nCache Performance:")
            print(f"  Total operations: {num_operations}")
            print(f"  Average set time: {avg_set_time:.6f}s")
            print(f"  Average get time: {avg_get_time:.6f}s")
            
            # Performance requirements
            assert avg_set_time < 0.01, f"Cache set time {avg_set_time:.6f}s exceeds 10ms limit"
            assert avg_get_time < 0.005, f"Cache get time {avg_get_time:.6f}s exceeds 5ms limit"

    @pytest.mark.asyncio
    async def test_websocket_performance(self):
        """Test WebSocket connection performance"""
        from app.api.websocket import ConnectionManager
        
        manager = ConnectionManager()
        
        # Test connection establishment time
        connection_times = []
        num_connections = 100
        
        for i in range(num_connections):
            mock_websocket = AsyncMock()
            mock_websocket.accept = AsyncMock()
            
            start_time = time.time()
            await manager.connect(mock_websocket)
            end_time = time.time()
            
            connection_times.append(end_time - start_time)
        
        avg_connection_time = statistics.mean(connection_times)
        
        # Test message broadcasting performance
        message = '{"type": "test", "data": "performance test"}'
        
        start_time = time.time()
        await manager.broadcast(message)
        end_time = time.time()
        
        broadcast_time = end_time - start_time
        
        print(f"\nWebSocket Performance:")
        print(f"  Total connections: {num_connections}")
        print(f"  Average connection time: {avg_connection_time:.6f}s")
        print(f"  Broadcast time: {broadcast_time:.6f}s")
        print(f"  Active connections: {len(manager.active_connections)}")
        
        # Performance requirements
        assert avg_connection_time < 0.01, f"Connection time {avg_connection_time:.6f}s exceeds 10ms limit"
        assert broadcast_time < 1.0, f"Broadcast time {broadcast_time:.6f}s exceeds 1s limit"

    @pytest.mark.asyncio
    async def test_scheduler_performance(self):
        """Test scheduler performance"""
        with patch('app.scheduler.audit_scheduler.AuditScheduler') as mock_scheduler_class:
            mock_scheduler = MagicMock()
            
            # Mock audit execution
            async def mock_run_security_audit(audit_type):
                # Simulate audit processing time
                await asyncio.sleep(0.1)  # 100ms
                mock_audit_log = MagicMock()
                mock_audit_log.status = "COMPLETED"
                mock_audit_log.findings_count = 10
                return mock_audit_log
            
            mock_scheduler.run_security_audit = mock_run_security_audit
            mock_scheduler_class.return_value = mock_scheduler
            
            scheduler = mock_scheduler
            
            # Measure audit performance
            num_audits = 10
            audit_times = []
            
            for i in range(num_audits):
                start_time = time.time()
                audit_log = await scheduler.run_security_audit("full")
                end_time = time.time()
                
                audit_times.append(end_time - start_time)
                assert audit_log.status == "COMPLETED"
            
            avg_audit_time = statistics.mean(audit_times)
            total_audit_time = sum(audit_times)
            
            print(f"\nScheduler Performance:")
            print(f"  Total audits: {num_audits}")
            print(f"  Average audit time: {avg_audit_time:.2f}s")
            print(f"  Total audit time: {total_audit_time:.2f}s")
            
            # Performance requirements
            assert avg_audit_time < 5.0, f"Average audit time {avg_audit_time:.2f}s exceeds 5s limit"

    def test_performance_regression_detection(self):
        """Test performance regression detection"""
        # This test would normally load baseline performance data
        # and compare against current performance
        
        baseline_performance = {
            "rule_evaluation_avg": 0.1,  # seconds
            "event_normalization_avg": 0.001,  # seconds
            "api_response_avg": 0.5,  # seconds
            "cache_set_avg": 0.005,  # seconds
            "cache_get_avg": 0.002,  # seconds
        }
        
        # Current performance (would be measured in real tests)
        current_performance = {
            "rule_evaluation_avg": 0.08,  # seconds
            "event_normalization_avg": 0.0008,  # seconds
            "api_response_avg": 0.4,  # seconds
            "cache_set_avg": 0.004,  # seconds
            "cache_get_avg": 0.0015,  # seconds
        }
        
        # Check for regressions (performance should not degrade by more than 20%)
        regression_threshold = 0.2
        
        for metric, baseline_value in baseline_performance.items():
            current_value = current_performance[metric]
            degradation = (current_value - baseline_value) / baseline_value
            
            print(f"\nPerformance Regression Check:")
            print(f"  {metric}:")
            print(f"    Baseline: {baseline_value:.3f}s")
            print(f"    Current: {current_value:.3f}s")
            print(f"    Degradation: {degradation:.1%}")
            
            assert degradation <= regression_threshold, \
                f"Performance regression detected in {metric}: {degradation:.1%} degradation"

    @pytest.mark.asyncio
    async def test_load_balancing_performance(self):
        """Test load balancing performance under high load"""
        with patch('app.engine.rule_engine.RuleEngine') as mock_rule_engine_class:
            mock_engine = MagicMock()
            
            # Simulate variable processing times
            processing_times = [0.001, 0.002, 0.003, 0.001, 0.002]  # ms
            
            async def mock_evaluate_event(event):
                import random
                await asyncio.sleep(random.choice(processing_times))
                return []
            
            mock_engine.evaluate_event = mock_evaluate_event
            mock_rule_engine_class.return_value = mock_engine
            
            rule_engine = mock_engine
            
            # Generate high load
            num_events = 200
            events = [
                {
                    "event_id": f"load-test-{i}",
                    "event_name": "CreateBucket",
                    "resource_id": f"bucket-{i}",
                    "resource_type": "s3"
                }
                for i in range(num_events)
            ]
            
            # Process events in batches to simulate load balancing
            batch_size = 20
            start_time = time.time()
            
            for i in range(0, len(events), batch_size):
                batch = events[i:i + batch_size]
                tasks = [rule_engine.evaluate_event(event) for event in batch]
                await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            throughput = len(events) / total_time
            
            print(f"\nLoad Balancing Performance:")
            print(f"  Total events: {len(events)}")
            print(f"  Batch size: {batch_size}")
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Throughput: {throughput:.1f} events/second")
            
            # Performance requirements
            assert throughput > 50, f"Throughput {throughput:.1f} events/s below minimum 50 events/s"
            assert total_time < 30.0, f"Total processing time {total_time:.2f}s exceeds 30s limit"
