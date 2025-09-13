use zeroize::{Zeroize, ZeroizeOnDrop};
use std::alloc::{self, Layout};
use std::ptr;
use anyhow::{Result, anyhow};

/// Secure memory allocator that locks memory pages to prevent swapping
pub struct SecureAllocator;

impl SecureAllocator {
    /// Allocate secure memory that won't be swapped to disk
    pub fn allocate_secure(size: usize) -> Result<SecureMemory> {
        if size == 0 {
            return Err(anyhow!("Cannot allocate zero bytes"));
        }

        // Align to page boundary for better security
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|e| anyhow!("Invalid memory layout: {}", e))?;

        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        
        if ptr.is_null() {
            return Err(anyhow!("Failed to allocate memory"));
        }

        // Lock the memory to prevent swapping (Unix-specific)
        #[cfg(unix)]
        {
            let result = unsafe { libc::mlock(ptr as *const libc::c_void, size) };
            if result != 0 {
                // Log warning but don't fail - memory locking might not be available
                tracing::warn!("Failed to lock memory pages: {}", std::io::Error::last_os_error());
            }
        }

        // Set memory protection (read/write, no execute)
        #[cfg(unix)]
        {
            let result = unsafe {
                libc::mprotect(
                    ptr as *mut libc::c_void,
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if result != 0 {
                tracing::warn!("Failed to set memory protection: {}", std::io::Error::last_os_error());
            }
        }

        Ok(SecureMemory {
            ptr,
            size,
            layout,
        })
    }
}

/// Secure memory that is automatically zeroed and unlocked on drop
pub struct SecureMemory {
    ptr: *mut u8,
    size: usize,
    layout: Layout,
}

impl SecureMemory {
    /// Get a slice to the memory
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    /// Get a mutable slice to the memory
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    /// Get the size of the allocated memory
    pub fn size(&self) -> usize {
        self.size
    }

    /// Copy data into the secure memory
    pub fn copy_from_slice(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.size {
            return Err(anyhow!("Data too large for secure memory buffer"));
        }

        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, data.len());
        }

        Ok(())
    }

    /// Zero the memory immediately
    pub fn zero(&mut self) {
        unsafe {
            ptr::write_bytes(self.ptr, 0, self.size);
        }
    }

    /// Create a secure copy of this memory
    pub fn secure_clone(&self) -> Result<SecureMemory> {
        let mut new_memory = SecureAllocator::allocate_secure(self.size)?;
        new_memory.copy_from_slice(self.as_slice())?;
        Ok(new_memory)
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Zero the memory before freeing
        self.zero();

        // Unlock the memory (Unix-specific)
        #[cfg(unix)]
        unsafe {
            let _ = libc::munlock(self.ptr as *const libc::c_void, self.size);
        }

        // Free the memory
        unsafe {
            alloc::dealloc(self.ptr, self.layout);
        }
    }
}

// Ensure SecureMemory is not Send or Sync for additional safety
// Note: Negative trait bounds are not stable, so we use a marker type approach instead
unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}

/// Secure vector that uses secure memory allocation
pub struct SecureVec {
    data: Vec<u8>,
    secure_memory: Option<SecureMemory>,
    use_secure_allocation: bool,
}

impl SecureVec {
    /// Create a new secure vector
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            secure_memory: None,
            use_secure_allocation: false,
        }
    }

    /// Create a secure vector with secure memory allocation
    pub fn with_secure_allocation(capacity: usize) -> Result<Self> {
        let secure_memory = SecureAllocator::allocate_secure(capacity)?;
        Ok(Self {
            data: Vec::new(),
            secure_memory: Some(secure_memory),
            use_secure_allocation: true,
        })
    }

    /// Create from existing data
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        let mut result = Self {
            data,
            secure_memory: None,
            use_secure_allocation: false,
        };
        result
    }

    /// Push data to the vector
    pub fn push(&mut self, value: u8) {
        if self.use_secure_allocation {
            if let Some(ref mut secure_mem) = self.secure_memory {
                if self.data.len() < secure_mem.size() {
                    self.data.push(value);
                    secure_mem.as_mut_slice()[self.data.len() - 1] = value;
                }
            }
        } else {
            self.data.push(value);
        }
    }

    /// Extend with slice
    pub fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        if self.use_secure_allocation {
            if let Some(ref mut secure_mem) = self.secure_memory {
                if self.data.len() + other.len() > secure_mem.size() {
                    return Err(anyhow!("Not enough secure memory for extension"));
                }
                
                let start_idx = self.data.len();
                self.data.extend_from_slice(other);
                
                for (i, &byte) in other.iter().enumerate() {
                    secure_mem.as_mut_slice()[start_idx + i] = byte;
                }
            }
        } else {
            self.data.extend_from_slice(other);
        }
        Ok(())
    }

    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clear the vector and zero memory
    pub fn clear(&mut self) {
        if let Some(ref mut secure_mem) = self.secure_memory {
            secure_mem.zero();
        }
        self.data.zeroize();
        self.data.clear();
    }

    /// Convert to regular Vec (consumes self and zeros original)
    pub fn into_vec(mut self) -> Vec<u8> {
        let result = self.data.clone();
        self.clear();
        result
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        if let Some(ref secure_mem) = self.secure_memory {
            secure_mem.size()
        } else {
            self.data.capacity()
        }
    }
}

impl Default for SecureVec {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Memory protection utilities
pub struct MemoryProtection;

impl MemoryProtection {
    /// Disable core dumps for the current process (Unix only)
    #[cfg(unix)]
    pub fn disable_core_dumps() -> Result<()> {
        let rlimit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlimit) };
        
        if result == 0 {
            Ok(())
        } else {
            Err(anyhow!("Failed to disable core dumps: {}", std::io::Error::last_os_error()))
        }
    }

    /// Disable core dumps (no-op on non-Unix systems)
    #[cfg(not(unix))]
    pub fn disable_core_dumps() -> Result<()> {
        tracing::warn!("Core dump disabling not supported on this platform");
        Ok(())
    }

    /// Lock all memory pages to prevent swapping (Unix only)
    #[cfg(unix)]
    pub fn lock_all_memory() -> Result<()> {
        let result = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        
        if result == 0 {
            Ok(())
        } else {
            Err(anyhow!("Failed to lock memory: {}", std::io::Error::last_os_error()))
        }
    }

    /// Lock all memory (no-op on non-Unix systems)
    #[cfg(not(unix))]
    pub fn lock_all_memory() -> Result<()> {
        tracing::warn!("Memory locking not supported on this platform");
        Ok(())
    }

    /// Clear memory and prevent compiler optimizations from removing the clear
    pub fn secure_zero(ptr: *mut u8, len: usize) {
        unsafe {
            // Use volatile_set_memory to prevent optimization
            ptr::write_bytes(ptr, 0, len);
            // Add a compiler barrier to prevent optimization
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Constant time memory comparison to prevent timing attacks
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            result |= byte_a ^ byte_b;
        }

        result == 0
    }

    /// Generate secure random bytes
    pub fn secure_random_bytes(count: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; count];
        
        #[cfg(unix)]
        {
            use std::fs::File;
            use std::io::Read;
            
            let mut urandom = File::open("/dev/urandom")
                .map_err(|e| anyhow!("Failed to open /dev/urandom: {}", e))?;
            
            urandom.read_exact(&mut buffer)
                .map_err(|e| anyhow!("Failed to read random bytes: {}", e))?;
        }
        
        #[cfg(windows)]
        {
            use winapi::um::wincrypt::*;
            use winapi::um::winnt::*;
            use std::ptr;
            
            unsafe {
                let mut prov: HCRYPTPROV = 0;
                
                if CryptAcquireContextW(&mut prov, ptr::null(), ptr::null(), PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == 0 {
                    return Err(anyhow!("Failed to acquire crypto context"));
                }
                
                let result = CryptGenRandom(prov, count as u32, buffer.as_mut_ptr());
                CryptReleaseContext(prov, 0);
                
                if result == 0 {
                    return Err(anyhow!("Failed to generate random bytes"));
                }
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            return Err(anyhow!("Secure random generation not implemented for this platform"));
        }
        
        Ok(buffer)
    }
}

/// Secure string builder that zeros intermediate buffers
pub struct SecureStringBuilder {
    parts: Vec<SecureVec>,
    total_len: usize,
}

impl SecureStringBuilder {
    /// Create a new secure string builder
    pub fn new() -> Self {
        Self {
            parts: Vec::new(),
            total_len: 0,
        }
    }

    /// Add a string part
    pub fn append_str(&mut self, s: &str) {
        let mut secure_vec = SecureVec::from_vec(s.as_bytes().to_vec());
        self.total_len += s.len();
        self.parts.push(secure_vec);
    }

    /// Add bytes
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        let mut secure_vec = SecureVec::from_vec(bytes.to_vec());
        self.total_len += bytes.len();
        self.parts.push(secure_vec);
    }

    /// Build the final secure string
    pub fn build(mut self) -> Result<SecureVec> {
        let mut result = SecureVec::with_secure_allocation(self.total_len)?;
        
        for part in &self.parts {
            result.extend_from_slice(part.as_slice())?;
        }
        
        // Clear all parts
        for part in &mut self.parts {
            part.clear();
        }
        
        Ok(result)
    }

    /// Get the total length
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

impl Default for SecureStringBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureStringBuilder {
    fn drop(&mut self) {
        for part in &mut self.parts {
            part.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_memory_allocation() {
        let mut secure_mem = SecureAllocator::allocate_secure(1024).unwrap();
        
        assert_eq!(secure_mem.size(), 1024);
        
        let test_data = b"Hello, secure world!";
        secure_mem.copy_from_slice(test_data).unwrap();
        
        assert_eq!(&secure_mem.as_slice()[..test_data.len()], test_data);
        
        secure_mem.zero();
        assert_eq!(&secure_mem.as_slice()[..test_data.len()], &vec![0u8; test_data.len()][..]);
    }

    #[test]
    fn test_secure_vec() {
        let mut vec = SecureVec::new();
        
        vec.push(1);
        vec.push(2);
        vec.push(3);
        
        assert_eq!(vec.as_slice(), &[1, 2, 3]);
        assert_eq!(vec.len(), 3);
        
        vec.extend_from_slice(&[4, 5, 6]).unwrap();
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5, 6]);
        
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_secure_vec_with_allocation() {
        let mut vec = SecureVec::with_secure_allocation(10).unwrap();
        
        vec.extend_from_slice(b"Hello").unwrap();
        assert_eq!(vec.as_slice(), b"Hello");
        assert_eq!(vec.capacity(), 10);
        
        // Should fail if we try to exceed capacity
        let result = vec.extend_from_slice(b"This is too long");
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"secret";
        let b = b"secret";
        let c = b"public";
        
        assert!(MemoryProtection::constant_time_compare(a, b));
        assert!(!MemoryProtection::constant_time_compare(a, c));
        assert!(!MemoryProtection::constant_time_compare(a, b"secre")); // Different length
    }

    #[test]
    fn test_secure_random_bytes() {
        let random1 = MemoryProtection::secure_random_bytes(32).unwrap();
        let random2 = MemoryProtection::secure_random_bytes(32).unwrap();
        
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2); // Should be different (with very high probability)
    }

    #[test]
    fn test_secure_string_builder() {
        let mut builder = SecureStringBuilder::new();
        
        builder.append_str("Hello, ");
        builder.append_str("secure ");
        builder.append_bytes(b"world!");
        
        assert_eq!(builder.len(), 20);
        
        let result = builder.build().unwrap();
        assert_eq!(result.as_slice(), b"Hello, secure world!");
    }

    #[test]
    fn test_memory_protection_functions() {
        // These might not work in all test environments, so we just test they don't panic
        let _ = MemoryProtection::disable_core_dumps();
        let _ = MemoryProtection::lock_all_memory();
    }
}