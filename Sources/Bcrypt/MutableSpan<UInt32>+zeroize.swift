extension MutableSpan<UInt32> {
    /// Overwrites `buffer` with zeros in a way the optimizer cannot elide.
    @_optimize(none) @inline(never)
    @usableFromInline
    mutating func zeroize() {
        var i = 0
        while i < self.count {
            unsafe self[unchecked: i] = 0
            i &+= 1
        }
    }
}
