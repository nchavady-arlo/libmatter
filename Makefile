ifdef V
Q :=
else
Q := @
endif

OBJDIR ?= .

ifneq ($(PREFIX),)
CXX := $(PREFIX)g++
AR  := $(PREFIX)gcc-ar
endif
INSTALL ?= install
PKG_CONFIG ?= pkg-config

TARGET_LIB := libmatter.so

SRCS := \
	controller/MatterOperation.cpp \
	controller/MatterController.cpp \
	controller/MatterError.cpp \
	controller/MatterJsonUtils.cpp \
	controller/MatterCommand.cpp \
	controller/MatterSubscribe.cpp \
	controller/MatterPublish.cpp \
	controller/MinimalDataModelProvider.cpp

OBJS := $(addprefix $(OBJDIR)/, $(notdir $(SRCS:.cpp=.o)))

CXXFLAGS += -Wall -Werror -Wextra -Wno-unused-parameter
CXXFLAGS += -std=c++17 -fPIC -Os -g
CXXFLAGS += -I. -I./controller
CXXFLAGS += -I$(STAGING_DIR)/usr/include/matter
CXXFLAGS += -I$(STAGING_DIR)/usr/include/matter/config/$(TARGET_BASE_PLATFORM)
CXXFLAGS += -I$(STAGING_DIR)/usr/include/arlogw
CXXFLAGS += -DCHIP_SYSTEM_CONFIG_USE_SOCKETS=1
CXXFLAGS += -DCHIP_HAVE_CONFIG_H=1
CXXFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0 gio-2.0 2>/dev/null)

LDFLAGS += -shared -fPIC
LDFLAGS += $(shell $(PKG_CONFIG) --libs glib-2.0 gio-2.0 2>/dev/null)
LDFLAGS += $(shell $(PKG_CONFIG) --libs avahi-client 2>/dev/null)

LIBS += -Wl,--whole-archive -lCHIP -Wl,--no-whole-archive

all: $(OBJDIR)/$(TARGET_LIB)

$(OBJDIR)/$(TARGET_LIB): $(OBJS)
	$(Q)echo "  [LD] $(TARGET_LIB)"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: controller/%.cpp
	$(Q)echo "  [CXX] $(@:$(OBJDIR)/%=%)"
	$(Q)$(CXX) $(CXXFLAGS) -c -o $@ $<

install: $(OBJDIR)/$(TARGET_LIB)
	$(INSTALL) -D -m0755 $(OBJDIR)/$(TARGET_LIB) $(DESTDIR)/usr/lib/$(TARGET_LIB)
	$(INSTALL) -D -m0644 controller/matter_interface.h $(DESTDIR)/usr/include/matter_interface.h

install-staging: $(OBJDIR)/$(TARGET_LIB)
	$(INSTALL) -D -m0755 $(OBJDIR)/$(TARGET_LIB) $(STAGING_DIR)/usr/lib/$(TARGET_LIB)
	$(INSTALL) -D -m0644 controller/matter_interface.h $(STAGING_DIR)/usr/include/matter_interface.h

clean:
	-rm -f $(OBJDIR)/*.o $(OBJDIR)/$(TARGET_LIB)

.PHONY: all install install-staging clean
