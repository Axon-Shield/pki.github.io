# Performance Bottlenecks

## TL;DR

PKI operations frequently encounter performance bottlenecks during scaling from dozens to thousands (or millions) of certificates. Common bottlenecks include synchronous CA interactions, database queries without proper indexing, serial certificate operations, OCSP responder overload, and cryptographic computation limits. Performance optimization requires parallelization, caching, async operations, and architectural evolution.

**Key insight**: Most performance problems stem from serial operations, blocking I/O, and failure to leverage modern async patterns.

## Overview

Certificate management performance issues typically remain hidden until reaching critical scale. A system handling 100 certificates works fine with manual processes and synchronous operations. The same architecture collapses at 10,000 certificates and becomes completely unusable at 100,000+.

This page covers identifying, measuring, and resolving performance bottlenecks across the certificate lifecycle.

## Common Performance Anti-Patterns

### Anti-Pattern 1: Serial Certificate Operations

**The Problem**:
```python
# SLOW: Serial certificate issuance
def renew_all_certificates(certificates: List[Certificate]) -> List[Result]:
    """
    Serial renewal - processes one certificate at a time
    Time complexity: O(n * request_time)
    """
    results = []
    
    for cert in certificates:
        # Each operation blocks waiting for CA response
        try:
            new_cert = ca_client.issue_certificate(cert.csr)
            results.append(Success(new_cert))
        except Exception as e:
            results.append(Failure(cert, e))
    
    return results

# With 1000 certificates and 200ms per request:
# Total time: 1000 * 0.2s = 200 seconds (3+ minutes)
```

**The Solution**:
```python
import asyncio
from typing import List
import aiohttp

async def renew_certificates_parallel(
    certificates: List[Certificate],
    max_concurrency: int = 50
) -> List[Result]:
    """
    Parallel certificate renewal with concurrency limit
    Time complexity: O(n / concurrency * request_time)
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def renew_one(cert: Certificate) -> Result:
        async with semaphore:  # Limit concurrent operations
            try:
                async with aiohttp.ClientSession() as session:
                    new_cert = await ca_client.issue_certificate_async(
                        session, cert.csr
                    )
                    return Success(new_cert)
            except Exception as e:
                return Failure(cert, e)
    
    # Execute all renewals concurrently
    tasks = [renew_one(cert) for cert in certificates]
    results = await asyncio.gather(*tasks)
    
    return results

# With 1000 certificates, 200ms per request, 50 concurrent:
# Total time: (1000 / 50) * 0.2s = 4 seconds
# 50x improvement
```

**Performance Comparison**:
```python
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

class PerformanceComparison:
    """Compare different parallelization strategies"""
    
    def benchmark_serial(self, operations: List[Callable]) -> float:
        """Serial execution baseline"""
        start = time.time()
        results = []
        for op in operations:
            results.append(op())
        return time.time() - start
    
    def benchmark_threading(
        self,
        operations: List[Callable],
        workers: int = 50
    ) -> float:
        """Thread-based parallelization"""
        start = time.time()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda f: f(), operations))
        return time.time() - start
    
    def benchmark_multiprocessing(
        self,
        operations: List[Callable],
        workers: int = 8
    ) -> float:
        """Process-based parallelization"""
        start = time.time()
        with ProcessPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda f: f(), operations))
        return time.time() - start
    
    async def benchmark_asyncio(
        self,
        async_operations: List[Coroutine],
        concurrency: int = 100
    ) -> float:
        """Async/await parallelization"""
        start = time.time()
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def limited_op(op):
            async with semaphore:
                return await op
        
        results = await asyncio.gather(
            *[limited_op(op) for op in async_operations]
        )
        
        return time.time() - start

# Example benchmarks for 1000 operations at 100ms each:
# Serial:           100+ seconds
# Threading (50):   ~2 seconds  
# Asyncio (100):    ~1 second
# Multiprocess (8): ~12 seconds (worse due to IPC overhead)
```

### Anti-Pattern 2: Database Query Without Indexing

**The Problem**:
```sql
-- SLOW: Full table scan on every expiry check
-- Query time: O(n) where n = total certificates

SELECT * FROM certificates 
WHERE not_after < NOW() + INTERVAL '30 days'
ORDER BY not_after;

-- With 1 million certificates:
-- Query time: 5+ seconds (full table scan)
-- Executed every minute = massive CPU waste
```

**The Solution**:
```sql
-- Create index on expiry date
CREATE INDEX idx_certificates_expiry ON certificates(not_after);

-- Same query now uses index
-- Query time: < 10ms (index seek)
-- 500x improvement

-- Additional useful indexes
CREATE INDEX idx_certificates_fingerprint ON certificates(fingerprint_sha256);
CREATE INDEX idx_certificates_hostname ON certificates USING gin(hostnames);
CREATE INDEX idx_certificates_owner ON certificates(owner_team);
CREATE INDEX idx_certificates_status ON certificates(status) WHERE status != 'revoked';

-- Composite indexes for common queries
CREATE INDEX idx_certificates_expiry_status ON certificates(not_after, status);
CREATE INDEX idx_certificates_owner_env ON certificates(owner_team, environment);
```

**Query Optimization**:
```python
from sqlalchemy import Index, func
from sqlalchemy.orm import Query

class OptimizedCertificateQueries:
    """Optimized database queries for certificate operations"""
    
    def get_expiring_certificates(
        self,
        days: int = 30,
        limit: int = 1000
    ) -> List[Certificate]:
        """
        Efficiently retrieve expiring certificates
        Uses index on not_after column
        """
        cutoff = datetime.now() + timedelta(days=days)
        
        return (
            self.session.query(Certificate)
            .filter(Certificate.not_after < cutoff)
            .filter(Certificate.status == 'active')
            .order_by(Certificate.not_after)
            .limit(limit)
            .all()
        )
    
    def bulk_update_status(
        self,
        certificate_ids: List[str],
        new_status: str
    ):
        """
        Bulk update avoiding N+1 queries
        """
        # SLOW: N individual updates
        # for cert_id in certificate_ids:
        #     cert = session.query(Certificate).get(cert_id)
        #     cert.status = new_status
        
        # FAST: Single bulk update
        self.session.query(Certificate).filter(
            Certificate.id.in_(certificate_ids)
        ).update(
            {Certificate.status: new_status},
            synchronize_session=False
        )
        
        self.session.commit()
    
    def get_certificates_by_owner_efficient(
        self,
        owner: str
    ) -> List[Certificate]:
        """
        Efficient query with selective loading
        """
        return (
            self.session.query(Certificate)
            .filter(Certificate.owner_team == owner)
            .options(
                # Only load needed columns
                load_only(
                    Certificate.id,
                    Certificate.subject_cn,
                    Certificate.not_after
                )
            )
            .all()
        )
```

**Monitoring Query Performance**:
```sql
-- PostgreSQL: Enable query logging for slow queries
ALTER DATABASE certificates SET log_min_duration_statement = 1000;  -- Log queries > 1s

-- Identify slow queries
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    max_time
FROM pg_stat_statements
WHERE mean_time > 100  -- Queries averaging > 100ms
ORDER BY mean_time DESC
LIMIT 20;

-- Analyze query plan
EXPLAIN ANALYZE
SELECT * FROM certificates 
WHERE not_after < NOW() + INTERVAL '30 days'
ORDER BY not_after;
```

### Anti-Pattern 3: Synchronous CA Interactions

**The Problem**:
```python
class SynchronousCAClient:
    """Blocking CA operations kill throughput"""
    
    def issue_certificate(self, csr: str) -> Certificate:
        """
        Synchronous certificate issuance
        Blocks thread waiting for CA response (200-2000ms)
        """
        response = requests.post(
            f"{self.ca_url}/issue",
            json={'csr': csr},
            timeout=30  # Block for up to 30 seconds
        )
        
        if response.status_code == 200:
            return Certificate(response.json())
        else:
            raise CAError(response.text)
    
    def process_issuance_queue(self, queue: List[CSR]):
        """
        Process queue serially - disaster at scale
        100 requests * 500ms avg = 50 seconds minimum
        """
        for csr in queue:
            try:
                cert = self.issue_certificate(csr)
                self.store_certificate(cert)
            except CAError as e:
                self.handle_error(csr, e)
```

**The Solution**:
```python
import aiohttp
import asyncio
from typing import List, AsyncGenerator

class AsyncCAClient:
    """Non-blocking CA operations for high throughput"""
    
    def __init__(self, ca_url: str, max_concurrency: int = 100):
        self.ca_url = ca_url
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.session = None
    
    async def __aenter__(self):
        """Create persistent connection pool"""
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=100,  # Connection pool size
                ttl_dns_cache=300
            ),
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, *args):
        await self.session.close()
    
    async def issue_certificate_async(self, csr: str) -> Certificate:
        """
        Async certificate issuance
        Non-blocking - can handle 100s concurrently
        """
        async with self.semaphore:
            async with self.session.post(
                f"{self.ca_url}/issue",
                json={'csr': csr}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return Certificate(data)
                else:
                    text = await response.text()
                    raise CAError(text)
    
    async def process_issuance_queue(
        self,
        queue: List[CSR]
    ) -> AsyncGenerator[Result, None]:
        """
        Process entire queue concurrently with backpressure
        100 requests at 500ms avg = ~1-2 seconds total
        """
        async def issue_with_retry(csr: CSR) -> Result:
            for attempt in range(3):
                try:
                    cert = await self.issue_certificate_async(csr)
                    await self.store_certificate_async(cert)
                    return Success(cert)
                except CAError as e:
                    if attempt == 2:  # Last attempt
                        return Failure(csr, e)
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # Process all CSRs concurrently
        tasks = [issue_with_retry(csr) for csr in queue]
        
        # Yield results as they complete
        for coro in asyncio.as_completed(tasks):
            yield await coro
```

### Anti-Pattern 4: Crypto Operations Without Hardware Acceleration

**The Problem**:
```python
# SLOW: Software-only RSA operations
def generate_keypair_slow(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Pure Python/software RSA key generation
    2048-bit: ~100-200ms
    4096-bit: ~2-5 seconds
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    return serialize_keypair(private_key)

# At scale: 10,000 keys = 30-50 minutes
```

**The Solution**:
```python
# FAST: Use hardware acceleration when available
import os

def generate_keypair_fast(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Use hardware acceleration (AES-NI, AVX2, etc.)
    2048-bit: ~10-20ms with hardware
    10-20x faster than software-only
    """
    # cryptography library automatically uses hardware when available
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    # Ensure we're using backend with hardware support
    backend = default_backend()
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=backend
    )
    
    return serialize_keypair(private_key)

# Consider ECDSA for even better performance
def generate_ecdsa_keypair() -> Tuple[bytes, bytes]:
    """
    ECDSA P-256 key generation
    ~5ms per key (20x faster than RSA-2048)
    Smaller keys, faster operations
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    
    private_key = ec.generate_private_key(
        ec.SECP256R1()  # P-256 curve
    )
    
    return serialize_keypair(private_key)
```

**Offload to Hardware Security Module (HSM)**:
```python
import pkcs11
from pkcs11 import Mechanism

class HSMKeyGeneration:
    """
    Offload key generation to HSM
    Throughput: 100-1000+ keys/second
    """
    
    def __init__(self, pkcs11_lib: str, slot: int, pin: str):
        self.lib = pkcs11.lib(pkcs11_lib)
        self.token = self.lib.get_token(slot_id=slot)
        self.pin = pin
    
    def generate_keypair_hsm(self, key_size: int = 2048) -> str:
        """
        Generate RSA keypair in HSM
        Returns key handle (not actual key material)
        """
        with self.token.open(user_pin=self.pin) as session:
            # Generate keypair in hardware
            public_key, private_key = session.generate_keypair(
                Mechanism.RSA_PKCS_KEY_PAIR_GEN,
                {
                    'PUBLIC_EXPONENT': b'\x01\x00\x01',  # 65537
                    'MODULUS_BITS': key_size,
                }
            )
            
            # Return handle for later use
            return private_key.id.hex()
    
    def sign_csr_hsm(self, csr_data: bytes, key_handle: str) -> bytes:
        """
        Sign CSR using HSM-stored key
        Hardware performs signature operation
        """
        with self.token.open(user_pin=self.pin) as session:
            # Find key by handle
            private_key = session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                id=bytes.fromhex(key_handle)
            )
            
            # Sign in hardware
            signature = private_key.sign(
                csr_data,
                mechanism=Mechanism.SHA256_RSA_PKCS
            )
            
            return signature
```

### Anti-Pattern 5: OCSP Responder Overload

**The Problem**:
```python
class OCSPResponder:
    """Naive OCSP responder - dies under load"""
    
    def handle_request(self, ocsp_request: bytes) -> bytes:
        """
        Check revocation status for each request
        No caching, synchronous database query
        """
        # Parse request
        req = ocsp.load_der_ocsp_request(ocsp_request)
        cert_id = req.certificate_id
        
        # Query database (SLOW - no caching)
        revocation_status = self.db.query(
            "SELECT status FROM revoked_certs WHERE serial = ?",
            cert_id.serial_number
        )
        
        # Build response
        response = build_ocsp_response(cert_id, revocation_status)
        return response.public_bytes(serialization.Encoding.DER)

# Problem: Every OCSP check = database query
# At 10,000 req/s: 10,000 DB queries/second
# Database melts
```

**The Solution**:
```python
import redis
from functools import lru_cache
from cryptography import x509
from cryptography.x509 import ocsp

class CachedOCSPResponder:
    """High-performance OCSP responder with caching"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.cache_ttl = 300  # 5 minutes
        
        # Pre-build OCSP responses for all certificates
        self.prebuild_responses()
    
    def prebuild_responses(self):
        """
        Pre-build and cache OCSP responses
        Update on revocation events, not per request
        """
        all_certs = self.db.get_all_active_certificates()
        
        for cert in all_certs:
            # Build response once
            response = self.build_ocsp_response(
                cert.serial_number,
                status='good'
            )
            
            # Cache in Redis
            cache_key = f"ocsp:{cert.serial_number}"
            self.redis.setex(
                cache_key,
                self.cache_ttl,
                response.public_bytes(serialization.Encoding.DER)
            )
    
    async def handle_request_cached(self, ocsp_request: bytes) -> bytes:
        """
        Handle OCSP request with caching
        Cache hit: <1ms response time
        Cache miss: ~10ms (build + cache)
        """
        # Parse request
        req = ocsp.load_der_ocsp_request(ocsp_request)
        cert_id = req.certificate_id
        serial = cert_id.serial_number
        
        # Check cache first
        cache_key = f"ocsp:{serial}"
        cached_response = self.redis.get(cache_key)
        
        if cached_response:
            return cached_response
        
        # Cache miss - build response
        revocation_status = await self.db.get_status_async(serial)
        response = self.build_ocsp_response(serial, revocation_status)
        response_bytes = response.public_bytes(serialization.Encoding.DER)
        
        # Cache for future requests
        self.redis.setex(cache_key, self.cache_ttl, response_bytes)
        
        return response_bytes
    
    def on_revocation_event(self, serial_number: int):
        """
        Update cached response when certificate revoked
        Push-based updates instead of pull-based
        """
        # Build revoked response
        response = self.build_ocsp_response(serial_number, status='revoked')
        response_bytes = response.public_bytes(serialization.Encoding.DER)
        
        # Update cache immediately
        cache_key = f"ocsp:{serial_number}"
        self.redis.setex(cache_key, self.cache_ttl, response_bytes)
        
        # Optionally: Invalidate CDN cache
        self.cdn.purge(f"/ocsp/{serial_number}")

# Performance improvement:
# Before: 10,000 req/s = 10,000 DB queries/s (fails)
# After:  10,000 req/s = ~50 DB queries/s (cache misses only)
# 200x reduction in database load
```

## Measuring Performance

### Key Metrics

```python
from prometheus_client import Histogram, Counter, Gauge
import time
from functools import wraps

# Define metrics
certificate_operation_duration = Histogram(
    'certificate_operation_duration_seconds',
    'Time spent in certificate operations',
    ['operation', 'status']
)

certificate_operations_total = Counter(
    'certificate_operations_total',
    'Total certificate operations',
    ['operation', 'status']
)

certificate_queue_size = Gauge(
    'certificate_queue_size',
    'Number of certificates waiting for processing',
    ['queue_type']
)

database_query_duration = Histogram(
    'database_query_duration_seconds',
    'Database query duration',
    ['query_type']
)

ca_request_duration = Histogram(
    'ca_request_duration_seconds',
    'CA request duration',
    ['operation', 'status']
)

def measure_operation(operation_name: str):
    """Decorator to measure operation performance"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                status = 'success'
                return result
            except Exception as e:
                status = 'failure'
                raise
            finally:
                duration = time.time() - start
                certificate_operation_duration.labels(
                    operation=operation_name,
                    status=status
                ).observe(duration)
                certificate_operations_total.labels(
                    operation=operation_name,
                    status=status
                ).inc()
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                status = 'success'
                return result
            except Exception as e:
                status = 'failure'
                raise
            finally:
                duration = time.time() - start
                certificate_operation_duration.labels(
                    operation=operation_name,
                    status=status
                ).observe(duration)
                certificate_operations_total.labels(
                    operation=operation_name,
                    status=status
                ).inc()
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# Usage
@measure_operation('certificate_issuance')
async def issue_certificate(csr: str) -> Certificate:
    """Measured certificate issuance"""
    return await ca_client.issue(csr)
```

### Performance Benchmarking

```python
import statistics
from typing import Callable, List
import asyncio

class PerformanceBenchmark:
    """Comprehensive performance testing"""
    
    async def benchmark_throughput(
        self,
        operation: Callable,
        num_operations: int = 1000,
        concurrency: int = 10
    ) -> Dict[str, float]:
        """
        Measure throughput of concurrent operations
        """
        semaphore = asyncio.Semaphore(concurrency)
        start_time = time.time()
        
        async def measured_operation():
            async with semaphore:
                start = time.time()
                await operation()
                return time.time() - start
        
        # Execute operations
        tasks = [measured_operation() for _ in range(num_operations)]
        durations = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        successful_durations = [
            d for d in durations if not isinstance(d, Exception)
        ]
        
        total_time = time.time() - start_time
        
        return {
            'total_operations': num_operations,
            'successful': len(successful_durations),
            'failed': num_operations - len(successful_durations),
            'total_time': total_time,
            'throughput': len(successful_durations) / total_time,
            'avg_latency': statistics.mean(successful_durations),
            'p50_latency': statistics.median(successful_durations),
            'p95_latency': statistics.quantiles(successful_durations, n=20)[18],
            'p99_latency': statistics.quantiles(successful_durations, n=100)[98],
            'max_latency': max(successful_durations),
        }
    
    async def benchmark_scaling(
        self,
        operation: Callable,
        concurrency_levels: List[int] = [1, 10, 50, 100, 200]
    ) -> Dict[int, Dict]:
        """
        Test performance at different concurrency levels
        """
        results = {}
        
        for concurrency in concurrency_levels:
            print(f"Testing concurrency: {concurrency}")
            results[concurrency] = await self.benchmark_throughput(
                operation,
                num_operations=1000,
                concurrency=concurrency
            )
        
        return results
    
    def print_scaling_report(self, results: Dict[int, Dict]):
        """Print formatted scaling report"""
        print("\n" + "="*80)
        print("PERFORMANCE SCALING REPORT")
        print("="*80)
        print(f"{'Concurrency':<12} {'Throughput':<15} {'P50':<10} {'P95':<10} {'P99':<10}")
        print("-"*80)
        
        for concurrency, metrics in sorted(results.items()):
            print(
                f"{concurrency:<12} "
                f"{metrics['throughput']:<15.2f} "
                f"{metrics['p50_latency']*1000:<10.1f} "
                f"{metrics['p95_latency']*1000:<10.1f} "
                f"{metrics['p99_latency']*1000:<10.1f}"
            )
        
        print("="*80)

# Example usage
async def main():
    benchmark = PerformanceBenchmark()
    
    # Benchmark certificate issuance
    results = await benchmark.benchmark_scaling(
        operation=lambda: ca_client.issue_certificate_async(test_csr),
        concurrency_levels=[1, 10, 50, 100, 200]
    )
    
    benchmark.print_scaling_report(results)

# Output example:
# ================================================================================
# PERFORMANCE SCALING REPORT
# ================================================================================
# Concurrency    Throughput      P50        P95        P99       
# --------------------------------------------------------------------------------
# 1              4.85            206.1      215.3      220.5     
# 10             48.23           207.3      225.1      245.7     
# 50             195.12          255.2      301.5      350.2     
# 100            285.43          349.7      425.1      480.3     
# 200            310.25          642.3      850.2      920.5     
# ================================================================================
```

## Architectural Patterns for Scale

### Pattern 1: Queue-Based Processing

```python
import asyncio
from asyncio import Queue
from typing import Optional

class CertificateProcessor:
    """
    Queue-based certificate processing for high throughput
    Decouples request acceptance from processing
    """
    
    def __init__(
        self,
        num_workers: int = 20,
        queue_size: int = 10000
    ):
        self.request_queue = Queue(maxsize=queue_size)
        self.num_workers = num_workers
        self.workers = []
    
    async def start(self):
        """Start worker pool"""
        self.workers = [
            asyncio.create_task(self.worker(i))
            for i in range(self.num_workers)
        ]
    
    async def stop(self):
        """Graceful shutdown"""
        # Send stop signal to all workers
        for _ in range(self.num_workers):
            await self.request_queue.put(None)
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers)
    
    async def worker(self, worker_id: int):
        """
        Worker coroutine - processes requests from queue
        """
        while True:
            # Get request from queue
            request = await self.request_queue.get()
            
            # Stop signal
            if request is None:
                break
            
            # Process request
            try:
                result = await self.process_certificate_request(request)
                await self.store_result(result)
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
            finally:
                self.request_queue.task_done()
    
    async def submit_request(
        self,
        request: CertificateRequest
    ) -> str:
        """
        Submit certificate request for processing
        Returns immediately with request ID
        """
        request_id = generate_request_id()
        request.id = request_id
        
        try:
            # Non-blocking put with timeout
            await asyncio.wait_for(
                self.request_queue.put(request),
                timeout=5.0
            )
            return request_id
        except asyncio.TimeoutError:
            raise QueueFullError("Processing queue at capacity")
    
    async def process_certificate_request(
        self,
        request: CertificateRequest
    ) -> CertificateResult:
        """Process individual certificate request"""
        # Issue certificate
        cert = await self.ca_client.issue(request.csr)
        
        # Deploy certificate
        if request.auto_deploy:
            await self.deploy_cert(cert, request.targets)
        
        return CertificateResult(
            request_id=request.id,
            certificate=cert,
            status='completed'
        )

# Usage
processor = CertificateProcessor(num_workers=50)
await processor.start()

# Submit thousands of requests - they queue for processing
for csr in csrs:
    request_id = await processor.submit_request(
        CertificateRequest(csr=csr, auto_deploy=True)
    )
    print(f"Request {request_id} queued")
```

### Pattern 2: Batch Processing

```python
class BatchProcessor:
    """
    Batch certificate operations for efficiency
    Trade latency for throughput
    """
    
    def __init__(
        self,
        batch_size: int = 100,
        batch_timeout: float = 1.0
    ):
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.pending_requests = []
        self.batch_lock = asyncio.Lock()
    
    async def add_to_batch(
        self,
        request: CertificateRequest
    ) -> Certificate:
        """
        Add request to batch, process when batch full or timeout
        """
        future = asyncio.Future()
        
        async with self.batch_lock:
            self.pending_requests.append((request, future))
            
            # Process if batch full
            if len(self.pending_requests) >= self.batch_size:
                asyncio.create_task(self.process_batch())
        
        # Also schedule timeout-based processing
        asyncio.create_task(self.process_batch_after_timeout())
        
        # Wait for result
        return await future
    
    async def process_batch_after_timeout(self):
        """Process batch after timeout"""
        await asyncio.sleep(self.batch_timeout)
        await self.process_batch()
    
    async def process_batch(self):
        """Process pending batch"""
        async with self.batch_lock:
            if not self.pending_requests:
                return
            
            batch = self.pending_requests[:]
            self.pending_requests.clear()
        
        # Process entire batch in parallel
        tasks = []
        for request, future in batch:
            task = self.process_single_request(request, future)
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def process_single_request(
        self,
        request: CertificateRequest,
        future: asyncio.Future
    ):
        """Process single request and set future result"""
        try:
            cert = await self.ca_client.issue(request.csr)
            future.set_result(cert)
        except Exception as e:
            future.set_exception(e)

# Usage pattern:
# Individual requests block until batch processed
# But processing happens in large parallel batches
cert1 = await batch_processor.add_to_batch(request1)  # May wait for batch
cert2 = await batch_processor.add_to_batch(request2)  # Added to same batch
# ... when batch full or timeout, all process in parallel
```

### Pattern 3: Caching Layer

```python
import hashlib
from datetime import datetime, timedelta

class CertificateCachingLayer:
    """
    Multi-level caching for certificate operations
    """
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.local_cache = {}  # In-memory L1 cache
        self.local_cache_ttl = 60  # 1 minute
        self.redis_ttl = 3600  # 1 hour
    
    async def get_certificate(
        self,
        fingerprint: str
    ) -> Optional[Certificate]:
        """
        Get certificate with multi-level caching
        L1: In-memory (1ms)
        L2: Redis (5-10ms)
        L3: Database (50-100ms)
        """
        # Check L1 cache (in-memory)
        if fingerprint in self.local_cache:
            cached_entry = self.local_cache[fingerprint]
            if cached_entry['expires_at'] > datetime.now():
                return cached_entry['certificate']
        
        # Check L2 cache (Redis)
        redis_key = f"cert:{fingerprint}"
        cached_data = await self.redis.get(redis_key)
        
        if cached_data:
            cert = deserialize_certificate(cached_data)
            
            # Populate L1 cache
            self.local_cache[fingerprint] = {
                'certificate': cert,
                'expires_at': datetime.now() + timedelta(seconds=self.local_cache_ttl)
            }
            
            return cert
        
        # Cache miss - query database (L3)
        cert = await self.db.get_certificate(fingerprint)
        
        if cert:
            # Populate both caches
            cert_data = serialize_certificate(cert)
            
            # L2 (Redis)
            await self.redis.setex(
                redis_key,
                self.redis_ttl,
                cert_data
            )
            
            # L1 (Memory)
            self.local_cache[fingerprint] = {
                'certificate': cert,
                'expires_at': datetime.now() + timedelta(seconds=self.local_cache_ttl)
            }
        
        return cert
    
    def cache_key_for_query(self, **kwargs) -> str:
        """Generate cache key for query parameters"""
        # Sort params for consistent key
        params = sorted(kwargs.items())
        params_str = json.dumps(params, sort_keys=True)
        return hashlib.sha256(params_str.encode()).hexdigest()
    
    async def get_certificates_cached(self, **query_params) -> List[Certificate]:
        """Cache query results"""
        cache_key = f"query:{self.cache_key_for_query(**query_params)}"
        
        # Check cache
        cached = await self.redis.get(cache_key)
        if cached:
            return deserialize_certificate_list(cached)
        
        # Execute query
        results = await self.db.query_certificates(**query_params)
        
        # Cache results (shorter TTL for queries)
        await self.redis.setex(
            cache_key,
            300,  # 5 minutes
            serialize_certificate_list(results)
        )
        
        return results
```

## Scaling Infrastructure

### Horizontal Scaling

```yaml
# Kubernetes deployment for scalable certificate management
apiVersion: apps/v1
kind: Deployment
metadata:
  name: certificate-processor
spec:
  replicas: 10  # Scale based on queue depth
  selector:
    matchLabels:
      app: certificate-processor
  template:
    metadata:
      labels:
        app: certificate-processor
    spec:
      containers:
      - name: processor
        image: certificate-processor:v1.2.3
        resources:
          requests:
            cpu: "1000m"
            memory: "2Gi"
          limits:
            cpu: "2000m"
            memory: "4Gi"
        env:
        - name: WORKER_CONCURRENCY
          value: "50"
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: url
---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: certificate-processor-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: certificate-processor
  minReplicas: 5
  maxReplicas: 50
  metrics:
  - type: Pods
    pods:
      metric:
        name: certificate_queue_size
      target:
        type: AverageValue
        averageValue: "100"  # Scale up if queue > 100 per pod
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Database Optimization

```python
# Connection pooling for database efficiency
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    'postgresql://user:pass@localhost/certs',
    poolclass=QueuePool,
    pool_size=20,  # Maintain 20 connections
    max_overflow=10,  # Allow 10 more if needed
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
)

# Read replicas for query distribution
class DatabaseRouter:
    """Route queries to appropriate database"""
    
    def __init__(self):
        self.writer = create_engine(WRITE_DB_URL, pool_size=10)
        self.readers = [
            create_engine(url, pool_size=20)
            for url in READ_REPLICA_URLS
        ]
        self.reader_index = 0
    
    def get_engine(self, write: bool = False):
        """Get appropriate database engine"""
        if write:
            return self.writer
        else:
            # Round-robin read replicas
            engine = self.readers[self.reader_index]
            self.reader_index = (self.reader_index + 1) % len(self.readers)
            return engine
```

## Conclusion

PKI performance bottlenecks stem from three core issues:

1. **Serial operations** - Solved with async/await and parallelization
2. **Blocking I/O** - Solved with async operations and connection pooling
3. **Lack of caching** - Solved with multi-level caching strategies

Scaling from thousands to millions of certificates requires architectural evolution:

- Queue-based processing for decoupling
- Batch operations for efficiency
- Aggressive caching at multiple levels
- Horizontal scaling with proper monitoring

The key: measure first, optimize second. Use metrics to identify actual bottlenecks rather than optimizing prematurely.
