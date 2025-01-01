pub fn nextPowerOf2(value: usize) usize {
    var v = value -% 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v +% 1;
}
