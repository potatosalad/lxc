NAME=lxc
VERSION=0.8.0-rc2_david
PKGVERSION=0.8.0~rc2~david
DOWNLOAD=git://github.com/potatosalad/lxc.git
TARBALL=$(NAME)-$(VERSION).tar.gz
TARDIR=$(NAME)-$(VERSION)
BUILDAREA=$(TARDIR)-build

GIT_DIR=$(shell test -d .git && echo ".git" || echo "$(NAME)/.git")

PREFIX=/usr

.PHONY: default
default: deb
package: deb

.PHONY: clean
clean:
	rm -f $(NAME)-* $(NAME)_* || true
	rm -fr $(TARDIR) || true
	rm -fr /tmp/$(BUILDAREA) || true
	rm -f *.deb
	rm -f *.rpm

$(NAME):
	test -d .git || git clone $(DOWNLOAD)

$(TARBALL): $(NAME)
	git --git-dir=$(GIT_DIR) fetch --all
	git --git-dir=$(GIT_DIR) archive --format tar.gz --output $(TARBALL) --prefix $(TARDIR)/ $(VERSION)

$(TARDIR): $(TARBALL)
	tar xfz $(TARBALL)

$(BUILDAREA):
	mkdir -p /tmp/$(BUILDAREA)

#--libdir=$(PREFIX)/lib/x86_64-linux-gnu/lxc
#--libexecdir=$(PREFIX)/lib/x86_64-linux-gnu/lxc
#--with-rootfs-path=$(PREFIX)/lib/x86_64-linux-gnu/lxc

build: $(TARDIR) $(BUILDAREA)
	cd $(TARDIR); \
	./autogen.sh; \
	./configure \
		--prefix=$(PREFIX) \
		--localstatedir=/var \
		--sysconfdir=/etc \
		--enable-doc; \
	make; make install DESTDIR=/tmp/$(BUILDAREA)

.PHONY: deb
deb: build
	fpm -s dir -t deb -v $(PKGVERSION) -n $(NAME) --conflicts 'cgroup-bin' \
		--depends 'debconf (>= 0.5) | debconf-2.0' \
		--depends 'debhelper (>= 9)' \
		--depends 'autotools-dev' \
		--depends 'docbook-utils' \
		--depends 'libc6 (>= 2.8)' \
		--depends 'libcap2 (>= 2.10)' \
		--depends 'libcap-dev' \
		--depends 'linux-libc-dev' \
		--deb-pre-depends 'multiarch-support' \
		--maintainer 'Andrew Bennett <andrew@delorum.com>' \
		--url 'http://lxc.sourceforge.net/' \
		--description 'Linux Containers userspace tools' \
		--architecture native \
		--vendor "PagodaBox" \
		-C /tmp/$(BUILDAREA) .
