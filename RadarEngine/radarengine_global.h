#ifndef SIMRAD_GLOBAL_H
#define SIMRAD_GLOBAL_H

#include <QDebug>

#include <math.h>

#ifndef UINT8
#define UINT8 quint8
#endif
#ifndef UINT8_MAX
#define UINT8_MAX (255)
#endif
#ifndef UINT16
#define UINT16 quint16
#endif
#ifndef UINT32
#define UINT32 quint32
#endif

#ifndef PI
#define PI (3.1415926535897931160E0)
#endif

#ifndef deg2rad
#define deg2rad(x) ((x)*2 * PI / 360.0)
#endif
#ifndef rad2deg
#define rad2deg(x) ((x)*360.0 / (2 * PI))
#endif

#define WATCHDOG_TIMEOUT (10000)  // After 10s assume GPS and heading data is invalid
#define TIMED_OUT(t, timeout) (t >= timeout)

#define SPOKES (4096)               //  radars can generate up to 4096 spokes per rotation,
#define LINES_PER_ROTATION (2048)   // but use only half that in practice
#define HALF_LINES_PER_ROTATION (LINES_PER_ROTATION/2)   // but use only half that in practice
#define ONE_PER_FOUR_LINES_PER_ROTATION (LINES_PER_ROTATION/4)   // but use only half that in practice
#define THREE_PER_FOUR_LINES_PER_ROTATION (LINES_PER_ROTATION*3/4)   // but use only half that in practice

#define RETURNS_PER_LINE (512)      //  radars generate 512 separate values per range, at 8 bits each
#define DEGREES_PER_ROTATION (360)  // Classical math

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define MAX_OVERLAY_TRANSPARENCY (10)

// Use the above to convert from 'raw' headings sent by the radar (0..4095) into classical degrees
// (0..359) and back
#define SCALE_RAW_TO_DEGREES(raw) ((raw) * (double)DEGREES_PER_ROTATION / SPOKES)
#define SCALE_RAW_TO_DEGREES2048(raw) ((raw) * (double)DEGREES_PER_ROTATION / LINES_PER_ROTATION)
#define SCALE_DEGREES_TO_RAW(angle) ((int)((angle) * (double)SPOKES / DEGREES_PER_ROTATION))
#define SCALE_DEGREES_TO_RAW2048(angle) ((int)((angle) * (double)LINES_PER_ROTATION / DEGREES_PER_ROTATION))
#define MOD_DEGREES(angle) (fmod(angle + 2 * DEGREES_PER_ROTATION, DEGREES_PER_ROTATION))
#define MOD_ROTATION(raw) (((raw) + 2 * SPOKES) % SPOKES)
#define MOD_ROTATION2048(raw) (((raw) + 2 * LINES_PER_ROTATION) % LINES_PER_ROTATION)

enum BlobColour {
    BLOB_NONE,
    BLOB_HISTORY_0,
    BLOB_HISTORY_1,
    BLOB_HISTORY_2,
    BLOB_HISTORY_3,
    BLOB_HISTORY_4,
    BLOB_HISTORY_5,
    BLOB_HISTORY_6,
    BLOB_HISTORY_7,
    BLOB_HISTORY_8,
    BLOB_HISTORY_9,
    BLOB_HISTORY_10,
    BLOB_HISTORY_11,
    BLOB_HISTORY_12,
    BLOB_HISTORY_13,
    BLOB_HISTORY_14,
    BLOB_HISTORY_15,
    BLOB_HISTORY_16,
    BLOB_HISTORY_17,
    BLOB_HISTORY_18,
    BLOB_HISTORY_19,
    BLOB_HISTORY_20,
    BLOB_HISTORY_21,
    BLOB_HISTORY_22,
    BLOB_HISTORY_23,
    BLOB_HISTORY_24,
    BLOB_HISTORY_25,
    BLOB_HISTORY_26,
    BLOB_HISTORY_27,
    BLOB_HISTORY_28,
    BLOB_HISTORY_29,
    BLOB_HISTORY_30,
    BLOB_HISTORY_31,
    BLOB_WEAK, //33
    BLOB_INTERMEDIATE, //34
    BLOB_STRONG //35
};
#define BLOB_HISTORY_MAX BLOB_HISTORY_31 //32
#define BLOB_COLOURS (BLOB_STRONG + 1) //36
#define BLOB_HISTORY_COLOURS (BLOB_HISTORY_MAX - BLOB_NONE) //32

typedef enum ControlType
{
    CT_GAIN,
    CT_SEA,
    CT_RAIN,
    CT_INTERFERENCE_REJECTION,
    CT_TARGET_SEPARATION,
    CT_NOISE_REJECTION,
    CT_TARGET_BOOST,
    CT_TARGET_EXPANSION,
    CT_REFRESHRATE,
    CT_SCAN_SPEED,
    CT_BEARING_ALIGNMENT,
    CT_SIDE_LOBE_SUPPRESSION,
    CT_ANTENNA_HEIGHT,
    CT_LOCAL_INTERFERENCE_REJECTION,
    CT_MAX  // Keep this last, see below
} ControlType;

enum RadarReportType
{
    RADAR_STATE,
    RADAR_FILTER,
    RADAR_TYPE,
    RADAR_ALIGN,
    RADAR_SCAN_AND_SIGNAL
};
enum RadarState
{
    RADAR_OFF,
    RADAR_STANDBY,
    RADAR_TRANSMIT,
    RADAR_WAKING_UP
};

enum RadarFilter
{
    RADAR_GAIN,
    RADAR_RAIN,
    RADAR_SEA,
    RADAR_TARGET_BOOST,
    RADAR_LOCAL_INTERFERENCE_REJECTION,
    RADAR_TARGET_EXPANSION,
    RADAR_RANGE
};

enum RadarAlign
{
    RADAR_BEARING,
    RADAR_ANTENA
};
enum RadarScanSignal
{
    RADAR_SCAN_SPEED,
    RADAR_NOISE_REJECT,
    RADAR_TARGET_SEPARATION,
    RADAR_LOBE_SUPRESION,
    RADAR_INTERFERENT
};
struct ReportFilter
{
    UINT8 gain;
    UINT8 rain;
    UINT8 sea;
    UINT8 targetBoost;
    UINT8 LInterference;
    UINT8 targetExpan;
    UINT32 range;
};
struct ReportAlign
{
    int bearing;
    UINT16 antena_height;
};
struct ReportScanSignal
{
    UINT16 scan_speed;
    UINT8 noise_reject;
    UINT8 target_sep;
    UINT8 side_lobe_suppression;
    UINT8 local_interference_rejection;
};
struct RadarSettings
{
    bool show_rings;
    bool headingUp;
    bool show_compass;
    bool show_heading_marker;
    int last_scale;
    QString ip_data;
    uint port_data;
    QString ip_report;
    uint port_report;
    QString ip_command;
    uint port_command;
};
struct ARPASettings
{
    int min_contour_length;
    bool create_arpa_by_click;
    bool show;
};
struct RadarRange {
  int meters; //command to radar and display
  int actual_meters; //based on range feedback
  const char *name;
};

static const RadarRange g_ranges_metric[] =
{
    /* */
    {100, 176, "100 m"},
    {250, 439, "250 m"},
    {500, 879, "500 m"},
    {750, 1328, "750 m"},
//    {750, 2029, "750 m"},
    {1000, 1758, "1 km"},
//    {1000, 2841, "1 km"},
    {1500, 2637, "1.5 km"},
//    {1500, 4057, "1.5 km"},
//    {2000, 3514, "2 km"},
    {2000, 3516, "2 km"},
    {3000, 3573, "3 km"},
//    {3000, 8285, "3 km"},
    {4000, 7031, "4 km"},
//    {4000, 9940, "4 km"},
    {6000, 10547, "6 km"},
//    {6000, 16538, "6 km"},
    {8000, 14063, "8 km"},
//    {8000, 21263, "8 km"},
    {12000, 21094, "12 km"},
//    {12000, 31950, "12 km"},
    {16000, 28125, "16 km"},
//    {16000, -19411, "16 km"},
    {24000, -23348, "24 km"},
//    {24000, -1636, "24 km"},
    {36000, -2255, "36 km"},
    {48000, -23349, "48 km"},
//    {48000, -23349, "48 km"},
    {64000, -9286, "64 km"},
//    {64000, -23349, "64 km"},
    {72000, -2255, "72 km"},
    {96000, -23349, "96 km"}
};
struct GZSettings
{
    bool show;
    bool enable_alarm;
    bool circle_type;
    bool confirmed;
    uint timeout;
    uint notif_thr;
    quint64 time;
    double inner_range;
    double outer_range;
    double start_bearing;
    double end_bearing;
};
struct TrailSettings
{
    bool enable;
    int trail;
};

static const int METRIC_RANGE_COUNT = ARRAY_SIZE(g_ranges_metric);

extern RadarState state_radar;
extern ReportFilter filter;
extern ReportAlign align;
extern ReportScanSignal scanSignal;
extern RadarSettings radar_settings;
extern ARPASettings arpa_settings;
extern GZSettings gz_settings[3];
extern TrailSettings trail_settings;

extern double currentOwnShipLat;
extern double currentOwnShipLon;
extern double radarHeading;
extern double currentHeading;
extern bool gps_auto;
extern bool hdg_auto;
extern bool headingUp;

extern bool enable_mti;
extern int mti_value;

#endif // SIMRAD_GLOBAL_H
