# ipadecrypt-helper

来源: https://github.com/londek/ipadecrypt (MIT License,见同目录 LICENSE)

设备端脱壳 helper(arm64 可执行,127KB)。本 fork 直接 vendor 其编译产物,
由 collector 以 `decrypt <bundle-id> <.app路径> <out.ipa>` 调用,
spawn 挂起目标 → task_for_pid + vm_read 读内存已解密页 → 重建 IPA。
目标 App 无需注入任何东西。事件流(stdout 每行一个 `@evt` k=v 记录)供 web 显示实时进度。
