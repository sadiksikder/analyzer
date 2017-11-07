TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

# INCLUDEPATH += "C:/Program Files (x86)/GNU/GnuPG/include"

# LIBS += -L"C:/Program Files (x86)/GNU/GnuPG/lib"
# LIBS += "C:/Program Files (x86)/GNU/GnuPG/lib/libgcrypt.imp"

LIBS += -lgcrypt

SOURCES += main.c \
    decrypt.c \
    hex.c

HEADERS += \
    decrypt.h
