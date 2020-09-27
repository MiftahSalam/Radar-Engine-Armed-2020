#ifndef RTI_H
#define RTI_H

#include <QObject>
#include <QColor>
#include <QTimer>
#include <cstdlib>
#include <iostream>
#include <QtGlobal>
#include <QtOpenGL>
#include <QThread>
#include <QUdpSocket>
#include <QHostAddress>
#include <QMutex>
#include <QString>

#include "radarengine_global.h"

/*MAtrix definition*/
template <typename Ty, int N, int M = N>
struct Matrix {
  typedef Ty value_type;

  union {
    struct {
      Ty element[N][M];
    };
    struct {
      Ty flatten[N * M];
    };
  };

  // Access with bounds checking
  Ty& operator()(const int r, const int c) {
    Q_ASSERT(r >= 0 && r < N);
    Q_ASSERT(c >= 0 && c < M);
    return element[r][c];
  }

  const Ty operator()(const int r, const int c) const {
    Q_ASSERT(r >= 0 && r < N);
    Q_ASSERT(c >= 0 && c < M);
    return element[r][c];
  }

  // Return matrix transpose
  Matrix<Ty, M, N> Transpose() const {
    Matrix<Ty, M, N> result;
    for (int r = 0; r < N; ++r) {
      for (int c = 0; c < M; ++c) {
        result.element[c][r] = element[r][c];
      }
    }
    return result;
  }

  // Return matrix initialized to value
  Matrix<Ty, M, N> Init(Ty value) const {
    Matrix<Ty, M, N> result;
    for (int e = 0; e < M * N; ++e) {
      result.flatten[e] = Ty(value);
    }
    return result;
  }

  // Return matrix inverse
  Matrix<Ty, N, M> Inverse();

  Matrix<Ty, N, N> Identity() {
    Matrix<Ty, N, N> result = Matrix<Ty, N, N>();
    for (int i = 0; i < N * N; ++i) result.flatten[i] = Ty(0);
    for (int i = 0; i < N; ++i) result.element[i][i] = Ty(1);
    return result;
  }
};


// Matrix Inverse
// Matrix inverse helpers
namespace detail {
template <typename Ty, int N, int M>
struct inverse;

// Matrix inversion for 2x2 matrix
template <typename Ty>
struct inverse<Ty, 2, 2> {
  Matrix<Ty, 2, 2> operator()(const Matrix<Ty, 2, 2>& a) {
    Matrix<Ty, 2, 2> result;
    Ty det = a.element[0][0] * a.element[1][1] - a.element[0][1] * a.element[1][0];
    Q_ASSERT(det != 0);

    result.element[0][0] = a.element[1][1] / det;
    result.element[1][1] = a.element[0][0] / det;
    result.element[0][1] = -a.element[0][1] / det;
    result.element[1][0] = -a.element[1][0] / det;
    return result;
  }
};

}  // detail

// Define matrix inverse
template <typename Ty, int N, int M>
Matrix<Ty, N, M> Matrix<Ty, N, M>::Inverse() {
  return detail::inverse<Ty, N, M>()(*this);
}

//  Matrix operations
// Matrix product
template <typename Ty, int N, int M, int P>
Matrix<Ty, N, P> operator*(const Matrix<Ty, N, M>& a, const Matrix<Ty, M, P>& b) {
  Matrix<Ty, N, P> result;

  for (int r = 0; r < N; ++r) {
    for (int c = 0; c < P; ++c) {
      Ty accum = Ty(0);
      for (int i = 0; i < M; ++i) {
        accum += a.element[r][i] * b.element[i][c];
      }
      result.element[r][c] = accum;
    }
  }
  return result;
}

// Unary negation
template <typename Ty, int N, int M>
Matrix<Ty, N, M> operator-(const Matrix<Ty, N, M>& a) {
  Matrix<Ty, N, M> result;
  for (int e = 0; e < N * M; ++e) result.flatten[e] = -a.flatten[e];
  return result;
}

#define MATRIX_WITH_MATRIX_OPERATOR(op_symbol, op)                                            \
  template <typename Ty, int N, int M>                                                        \
  Matrix<Ty, N, M> operator op_symbol(const Matrix<Ty, N, M>& a, const Matrix<Ty, N, M>& b) { \
    Matrix<Ty, N, M> result;                                                                  \
    for (int e = 0; e < N * M; ++e) result.flatten[e] = a.flatten[e] op b.flatten[e];         \
    return result;                                                                            \
  }

MATRIX_WITH_MATRIX_OPERATOR(+, +)
MATRIX_WITH_MATRIX_OPERATOR(-, -)
#undef MATRIX_WITH_MATRIX_OPERATOR

#define MATRIX_WITH_SCALAR_OPERATOR(op_symbol, op)                              \
  template <typename Ty, int N, int M>                                          \
  Matrix<Ty, N, M> operator op_symbol(const Matrix<Ty, N, M>& a, Ty scalar) {   \
    Matrix<Ty, N, M> result;                                                    \
    for (int e = 0; e < N * M; ++e) result.flatten[e] = a.flatten[e] op scalar; \
    return result;                                                              \
  }

MATRIX_WITH_SCALAR_OPERATOR(+, +)
MATRIX_WITH_SCALAR_OPERATOR(-, -)
MATRIX_WITH_SCALAR_OPERATOR(*, *)
MATRIX_WITH_SCALAR_OPERATOR(/, /)
#undef MATRIX_WITH_SCALAR_OPERATOR

template <typename Ty, int N, int M>
Matrix<Ty, N, M> operator+(Ty scalar, const Matrix<Ty, N, M>& a) {
  return a + scalar;
}

template <typename Ty, int N, int M>
Matrix<Ty, N, M> operator*(Ty scalar, const Matrix<Ty, N, M>& a) {
  return a * scalar;
}

template <typename Ty, int N, int M>
Matrix<Ty, N, M> operator-(Ty scalar, const Matrix<Ty, N, M>& a) {
  return -a + scalar;
}


/******KALMAN**********/
#define NOISE (0.015)  // Allowed covariance of target speed in lat and lon
                      // critical for the performance of target tracking
                      // lower value makes target go straight
                      // higher values allow target to make curves

class LocalPosition {
  // position in meters relative to own ship position
 public:
  double lat;
  double lon;
  double dlat_dt;  // meters per second
  double dlon_dt;
  double sd_speed_m_s;  // standard deviation of the speed m / sec

};

class Polar {
 public:
  int angle;
  int r;
  quint64 time;  // wxGetUTCTimeMillis
};

static Matrix<double, 4, 2> ZeroMatrix42;
static Matrix<double, 2, 4> ZeroMatrix24;
static Matrix<double, 4> ZeroMatrix4;
static Matrix<double, 2> ZeroMatrix2;

class KalmanFilter : public QObject
{
    Q_OBJECT
public:
    explicit KalmanFilter(QObject *parent = 0);
    void SetMeasurement(Polar* pol, LocalPosition* x, Polar* expected, int range);
    void Update_P();
    void Predict(LocalPosition* xx, double delta_time);
    void ResetFilter();

    Matrix<double, 4> A;
    Matrix<double, 4> AT;
    Matrix<double, 4, 2> W;
    Matrix<double, 2, 4> WT;
    Matrix<double, 2, 4> H;
    Matrix<double, 4, 2> HT;
    Matrix<double, 4> P;
    Matrix<double, 2> Q;
    Matrix<double, 2> R;
    Matrix<double, 4, 2> K;
    Matrix<double, 4> I;

};


/*******draw utility*********/
struct P2CLookupTable {
  GLfloat x[LINES_PER_ROTATION + 1][RETURNS_PER_LINE + 1];
  GLfloat y[LINES_PER_ROTATION + 1][RETURNS_PER_LINE + 1];
  int intx[LINES_PER_ROTATION + 1][RETURNS_PER_LINE + 1];
  int inty[LINES_PER_ROTATION + 1][RETURNS_PER_LINE + 1];
};
extern P2CLookupTable *lookupTable;
P2CLookupTable* GetP2CLookupTable();



/*********receive data class*********/
class RadarReceive : public QThread
{
    Q_OBJECT
public:
    explicit RadarReceive(QObject *parent = nullptr);
    ~RadarReceive();

    void exitReq();
    void setMulticastData(QString addr,uint port);
    void setMulticastReport(QString addr,uint port);

signals:
    void ProcessRadarSpoke(int angle_raw, QByteArray data,
                           int dataSize, int range_meter);
    void updateReport(quint8 report_type,quint8 report_field,quint32 value);
    void signal_changeAntena(QString sig);

protected:
    void run();

private:
    void processFrame(QByteArray data, int len);
    void processReport(QByteArray data, int len);

    bool exit_req;
    QString _data;
    uint _data_port;
    QString _report;
    uint _report_port;
    QMutex mutex;
    int radar_id;
};



/****************ri************************/
#define SECONDS_TO_REVOLUTIONS(x) ((x)*2 / 5)
#define TRAIL_MAX_REVOLUTIONS SECONDS_TO_REVOLUTIONS(600) + 1 //241
typedef UINT8 TrailRevolutionsAge;

class GZ;
class RI : public QObject
{
    Q_OBJECT
public:
    explicit RI(QObject *parent = nullptr,int id = 0);

    ~RI();

    struct line_history
    {
      UINT8 line[RETURNS_PER_LINE];
      quint64 time;
      double lat;
      double lon;
    };

    line_history m_history[LINES_PER_ROTATION];
    GLubyte old_strength_info[2048][512];
    GLubyte new_strength_info[2048][512];

    BlobColour m_colour_map[UINT8_MAX + 1];
    QColor m_colour_map_rgb[BLOB_COLOURS];

    quint64 radar_timeout;
    quint64 data_timeout;
    quint64 stay_alive_timeout;

    GZ *m_gz;
    RadarReceive *receiveThread;
    int radar_id;
    bool checkPix(int r, int angle);

signals:
    void signal_range_change(int range);
    void signal_stay_alive();
    void signal_plotRadarSpoke(int transparency, int angle, UINT8* data, size_t len);
    void signal_changeAntena(QString sig);

private slots:
    void receiveThread_Report(quint8 report_type,quint8 report_field,quint32 value);
    void radarReceive_ProcessRadarSpoke(int angle_raw, QByteArray data,
                                        int dataSize, int range_meter);
    void timerTimeout();
    void trigger_clearTrail();

    void trigger_ReqRadarSetting();

private:
    QTimer *timer;

    struct TrailBuffer
    {
        TrailRevolutionsAge relative_trails[LINES_PER_ROTATION][RETURNS_PER_LINE];
        TrailRevolutionsAge copy_of_relative_trails[LINES_PER_ROTATION][RETURNS_PER_LINE];

        double lat;
        double lon;
    };
    TrailBuffer m_trails;
    BlobColour m_trail_colour[TRAIL_MAX_REVOLUTIONS + 1];


    int m_range_meters;
    int rng_gz;
    int m_old_range;

    bool old_draw_trails;
    int old_trail;

    void ComputeColourMap();
    void ResetSpokes();
    void ZoomTrails(float zoom_factor);
    void ClearTrails();
    void ComputeTargetTrails();
};



/************************GZ************************/
typedef enum GZType { GZ_ARC, GZ_CIRCLE } GZType;
class GZ
{
public:
    GZ(RI *ri);


    ~GZ() { qDebug()<<Q_FUNC_INFO<<m_log_name<<"destroyed"; }
    void ResetBogeys()
    {
        m_bogey_count = 0;
        m_running_count = 0;
        m_last_in_guard_zone = false;
        m_last_angle = 0;
    }
    void ProcessSpoke(int angle, UINT8 *data, UINT8 *hist, int range);

    int GetBogeyCount()
    {
        return m_bogey_count;
    }
private:
    RI *m_ri;

    QString m_log_name;
    bool m_last_in_guard_zone;
    int m_last_angle;
    int m_bogey_count;    // complete cycle
    int m_running_count;  // current swipe
    GZType m_type;
    int m_start_bearing;
    int m_end_bearing;
    int m_inner_range;  // start in meters
    int m_outer_range;  // end   in meters

    void UpdateSettings();
};


/********************************arpa****************************/
#define MAX_NUMBER_OF_TARGETS (8)  // real max numer of targets is 1 less
#define MAX_CONTOUR_LENGTH (601)     // defines maximal size of target contour
#define SPEED_HISTORY (8)

typedef int target_status;
enum TargetProcessStatus { UNKNOWN, NOT_FOUND_IN_PASS1 };
enum PassN { PASS1, PASS2 };

class Position
{
public:
    double lat;
    double lon;
    double dlat_dt;   // m / sec
    double dlon_dt;   // m / sec
    quint64 time;  // millis
    double speed_kn;
    double sd_speed_kn;  // standard deviation of the speed in knots
};

Position Polar2Pos(Polar pol, Position own_ship, double range);

Polar Pos2Polar(Position p, Position own_ship, int range);

struct SpeedHistory
{
    double av;
    double hist[SPEED_HISTORY];
    double dif[SPEED_HISTORY];
    double sd;
    int nr;
};

class ARPATarget : public QObject
{
    Q_OBJECT
    friend class RA;

public:
    explicit ARPATarget(QObject *parent = 0,RI *ri=0);
    ~ARPATarget();
    void RefreshTarget(int dist);
    void SetStatusLost();
    QPointF blobPixelPosition();

    int m_target_id;
    Polar m_max_angle, m_min_angle, m_max_r, m_min_r;
    Polar m_max_angle_future, m_min_angle_future, m_max_r_future, m_min_r_future;
    bool future_first;
    double m_speed_kn;
    double m_course;
    int m_stationary;
    Position m_position;   // holds actual position of target
private:
    RI *m_ri;
    bool GetTarget(Polar* pol, int dist1);
    void ResetPixels();
    bool FindContourFromInside(Polar* pol);
    bool FindNearestContour(Polar* pol, int dist);
    bool MultiPix(int ang, int rad);
    bool Pix(int ang, int rad);
    int GetContour(Polar* p);

    KalmanFilter* m_kalman;
    target_status m_status;
    TargetProcessStatus m_pass1_result;
    SpeedHistory m_speeds;
    PassN m_pass_nr;
    int m_contour_length;
    quint64 m_refresh;  // time of last refresh
    quint64 m_time_future;
    int m_lost_count;
    bool m_check_for_duplicate;
    Polar m_contour[MAX_CONTOUR_LENGTH + 1];
    Polar m_expected;

    bool m_automatic;

};

class RA : public QObject
{
    Q_OBJECT
public:
    explicit RA(QObject *parent = 0,RI *ri=0);

    int m_number_of_targets,range_meters;
    ARPATarget *m_target[MAX_NUMBER_OF_TARGETS];

    bool MultiPix(int ang, int rad);
    void AcquireNewMARPATarget(Position p);
    int AcquireNewARPATarget(Polar pol, int status);
    void RefreshArpaTargets();
    void DeleteTarget(Position p);
    void DeleteAllTargets();
    void RadarLost()
    {
        DeleteAllTargets();  // Let ARPA targets disappear
    }

private:
    RI *m_ri;
    bool Pix(int ang, int rad);
    void AcquireOrDeleteMarpaTarget(Position target_pos, int status);
};




/**********************draw**************************/
class RD
{
 public:
  static RD* make_Draw(RI *ri, int draw_method);

  virtual void DrawRadarImage() = 0;
  virtual void ProcessRadarSpoke(int transparency, int angle, UINT8* data, size_t len) = 0;

  virtual ~RD() = 0;

  static QString methods;
  static QString GetDrawingMethods();

};
class RDVert : public RD
{
public:
    RDVert(RI* ri)
    {
        m_ri = ri;

        for (size_t i = 0; i < ARRAY_SIZE(m_vertices); i++)
        {
            m_vertices[i].count = 0;
            m_vertices[i].allocated = 0;
            m_vertices[i].timeout = 0;
            m_vertices[i].points = 0;
        }
        m_count = 0;
        m_oom = false;

        m_polarLookup = GetP2CLookupTable();
    }

    void DrawRadarImage();
    void ProcessRadarSpoke(int transparency, int angle, UINT8 *data, size_t len);

    ~RDVert()
    {
        for (size_t i = 0; i < LINES_PER_ROTATION; i++)
        {
            if (m_vertices[i].points)
            {
                free(m_vertices[i].points);
            }
        }
    }

private:
    RI* m_ri;

    static const int VERTEX_PER_TRIANGLE = 3;
    static const int VERTEX_PER_QUAD = 2 * VERTEX_PER_TRIANGLE;
    static const int MAX_BLOBS_PER_LINE = RETURNS_PER_LINE;

    struct VertexPoint
    {
        GLfloat x;
        GLfloat y;
        GLubyte red;
        GLubyte green;
        GLubyte blue;
        GLubyte alpha;
    };

    struct VertexLine
    {
        VertexPoint* points;
        qint64 timeout;
        size_t count;
        size_t allocated;
    };

    P2CLookupTable* m_polarLookup;

    VertexLine m_vertices[LINES_PER_ROTATION];
    unsigned int m_count;
    bool m_oom;

    void SetBlob(VertexLine* line, int angle_begin, int angle_end, int r1, int r2, GLubyte red, GLubyte green, GLubyte blue,
                 GLubyte alpha);
};




/**********************transmit*********************/
class radarTransmit : public QObject
{
    Q_OBJECT
public:
    explicit radarTransmit(QObject *parent = 0);

    void setControlValue(ControlType controlType, int value);
    void setMulticastData(QString addr,uint port);
    void setRange(int meters);

    QUdpSocket socket;
signals:

public slots:
    void RadarTx();
    void RadarStby();
    void RadarStayAlive();

private:
    QString _data;
    quint16 _data_port;
};

#endif // RTI_H
