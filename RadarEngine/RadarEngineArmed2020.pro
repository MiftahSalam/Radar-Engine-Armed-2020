QT       += network opengl

TARGET = radarengine-armed
TEMPLATE = lib
CONFIG += staticlib
#DEFINES += QT_NO_DEBUG_OUTPUT

# disable debug output in release mode
#CONFIG(release, debug|release): DEFINES += QT_NO_DEBUG_OUTPUT

SOURCES += \
    radarengine.cpp

HEADERS += radarengine.h \
    radarengine_global.h 

unix {
        target.path = /usr/lib
        INSTALLS = target
}
