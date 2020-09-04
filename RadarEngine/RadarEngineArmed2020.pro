QT       += network opengl

TARGET = radarengine-armed
TEMPLATE = lib
CONFIG += staticlib
#DEFINES += QT_NO_DEBUG_OUTPUT
DEFINES += UBUNTU16

# disable debug output in release mode
#CONFIG(release, debug|release): DEFINES += QT_NO_DEBUG_OUTPUT

SOURCES += \
    radarengine.cpp

HEADERS += radarengine.h \
    radarengine_global.h 

win32 {
    CONFIG += c++11 console
    message(Building for Windows)
    LIBS+= -lOpenGL32
}

unix {
        target.path = /usr/lib
        INSTALLS = target
}
