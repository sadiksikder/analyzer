QT += core
QT -= gui

TARGET = analyzer
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

LIBS += -lgcrypt\
        -lpcap


SOURCES += \
    main.c \
    decrypt.c \
    hex.c \
    decryptcomparator.c \
    decryptcomparator_server.c
    decrypt.c


HEADERS += \
    hex.h \
    header.h \
    tlsparser.h \
    decrypt.h
    decrypt.h
    hex.h

