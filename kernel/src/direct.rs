pub unsafe trait DirectCopy {
    unsafe fn copy_to(&self, other: *mut Self);
}
