QT += core
QT -= gui

TARGET = analyzer
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

LIBS += -lpcap

SOURCES += \
    main.c

HEADERS += \
    hex.h \
    header.h \
    tlsparser.h

