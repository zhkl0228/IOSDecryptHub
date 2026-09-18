# IOSDecryptHub 越狱插件
#
#   make deb              同时打 rootless + roothide
#   make deb-rootless
#   make deb-roothide

VERSION := 1.25.6

deb:
	@chmod +x build_deb.sh
	./build_deb.sh all

deb-rootless:
	@chmod +x build_deb.sh
	./build_deb.sh rootless

deb-roothide:
	@chmod +x build_deb.sh
	./build_deb.sh roothide

# 仿真回归测试：在 macOS 上把 daemon 跑成真机布局，用线上 release 走完整更新链路
test-updater:
	@chmod +x tests/updater_sim_test.sh
	./tests/updater_sim_test.sh

clean:
	rm -rf build/

.PHONY: deb deb-rootless deb-roothide test-updater clean
