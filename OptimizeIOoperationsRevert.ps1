# Optimize I/O operations
# Reduce I/O paging overhead and disabling last access updates which can help improve performance by reducing unnecessary I/O operations
Reg.exe Delete "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /f > $null 2>&1
Fsutil behavior set disablelastaccess 2 > $null 2>&1
