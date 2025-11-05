import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Arc2D;
import java.awt.image.BufferedImage;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.*;
import java.util.*;
import java.util.List;
import java.net.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import javax.bluetooth.*; // BlueCove / JSR-82
import javax.microedition.io.*; // StreamConnection, Connector, etc.

// ==================== MAIN CLASS (v2) ====================
/**
 * SmartAttendanceSystemv2
 * The main entry point for the enhanced Smart Attendance System.
 * This version features a beautifully redesigned UI with modern light colors,
 * new admin features, and critical bug fixes.
 * 
 * Test UI improvements:
 * javac -cp .:flatlaf-3.2.jar SmartAttendanceSystemv2.java
 * java -cp .:flatlaf-3.2.jar SmartAttendanceSystemv2
 * Evaluate: login flow, dashboard switching, attendance session startup animation
 * 
 * Run teacher app:
 * java -cp .:bluecove-2.1.1.jar:bluecove-bluez-2.1.1.jar SmartAttendanceSystemv2
 * On another device (student phone or laptop):
 * listen for broadcasts:
 *     nc -ul 5051
 * You should see repeating messages like:
 *     ATTENDANCE_SERVER|172.20.10.1|5050|SUBJ101|2025-11-04
 */

/**
 * Class to broadcast UDP packets for automatic discovery of the teacher's attendance server.
 * // TODO: Add session token or HMAC in broadcast message to prevent spoofing in public networks.
 */
class DiscoveryBroadcaster implements Runnable {
    private volatile boolean running = true;
    private final String teacherIp;
    private final int port;
    private final String subjectId;
    private final String date;

    public DiscoveryBroadcaster(String teacherIp, int port, String subjectId, String date) {
        this.teacherIp = teacherIp;
        this.port = port;
        this.subjectId = subjectId;
        this.date = date;
    }

    public void stop() { running = false; }

    @Override
    public void run() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            while (running) {
                String msg = "ATTENDANCE_SERVER|" + teacherIp + "|" + port + "|" + subjectId + "|" + date;
                byte[] buffer = msg.getBytes(StandardCharsets.UTF_8);
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length,
                    InetAddress.getByName("255.255.255.255"), 5051);
                socket.send(packet);
                System.out.println("[DISCOVERY] Broadcasting on 255.255.255.255:5051 -> " + msg);
                Thread.sleep(3000); // every 3 seconds
            }
        } catch (Exception e) {
            System.err.println("[DISCOVERY] Error: " + e.getMessage());
        } finally {
            System.out.println("[DISCOVERY] Broadcast stopped.");
        }
    }
}
public class SmartAttendanceSystemv2 {
    public static void main(String[] args) {
        try {
            // Set a modern, cross-platform look and feel for better UI consistency
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

            // Only set fonts, let system handle colors
            UIManager.put("Button.font", UIConstants.BUTTON_FONT);
            UIManager.put("Label.font", UIConstants.BODY_FONT);
            UIManager.put("TextField.font", UIConstants.BODY_FONT);
            UIManager.put("PasswordField.font", UIConstants.BODY_FONT);
            UIManager.put("ComboBox.font", UIConstants.BODY_FONT);
            UIManager.put("Table.font", UIConstants.BODY_FONT);
            UIManager.put("TableHeader.font", UIConstants.HEADER_FONT);

        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> {
            DataManager.getInstance().loadAllData();
            new LoginFrame();
        });
    }
}

// ==================== UI CONSTANTS ====================
/**
 * A central place to store all UI colors, fonts, and gradients
 * for a consistent and easily changeable look and feel.
 */
class UIConstants {
    // Modern Flat UI Colors - Light & Professional
    public static final Color PRIMARY = new Color(66, 133, 244); // Google Blue
    public static final Color PRIMARY_LIGHT = new Color(232, 240, 254); // Light blue background
    public static final Color PRIMARY_DARK = new Color(25, 103, 210); // Dark blue for contrast
    public static final Color BACKGROUND = Color.WHITE; // Standard white background
    public static final Color SURFACE = Color.WHITE; // Standard white surface
    public static final Color TEXT_DARK = new Color(32, 33, 36); // Google's dark grey
    public static final Color TEXT_MEDIUM = new Color(95, 99, 104); // Google's medium grey
    public static final Color TEXT_LIGHT = new Color(128, 134, 139); // Google's light grey
    public static final Color BORDER = new Color(218, 220, 224); // Light border
    public static final Color HOVER = new Color(245, 245, 245); // Light hover effect
    public static final Color SHADOW = new Color(0, 0, 0, 10); // Very subtle shadow

    // Standard Semantic Colors
    public static final Color SUCCESS = new Color(52, 168, 83); // Google green
    public static final Color SUCCESS_LIGHT = new Color(230, 244, 234); // Light green bg
    public static final Color SUCCESS_DARK = new Color(30, 142, 62); // Dark green
    public static final Color WARNING = new Color(251, 188, 4); // Google yellow
    public static final Color WARNING_LIGHT = new Color(254, 247, 224); // Light yellow bg
    public static final Color WARNING_DARK = new Color(217, 156, 0); // Dark yellow
    public static final Color ERROR = new Color(234, 67, 53); // Google red
    public static final Color ERROR_LIGHT = new Color(252, 232, 230); // Light red bg
    public static final Color ERROR_DARK = new Color(179, 29, 18); // Dark red

    // Enhanced Fonts with better hierarchy
    public static final Font TITLE_FONT = new Font("Segoe UI", Font.BOLD, 24); // Larger titles
    public static final Font SUBTITLE_FONT = new Font("Segoe UI", Font.BOLD, 18); // Subtitles
    public static final Font HEADER_FONT = new Font("Segoe UI", Font.BOLD, 16); // Section headers
    public static final Font BODY_FONT = new Font("Segoe UI", Font.PLAIN, 14); // Regular text
    public static final Font BODY_BOLD_FONT = new Font("Segoe UI", Font.BOLD, 14); // Bold text
    public static final Font CAPTION_FONT = new Font("Segoe UI", Font.PLAIN, 12); // Small text
    public static final Font BUTTON_FONT = new Font("Segoe UI", Font.BOLD, 14); // Button text
}

// Custom rounded border with shadow effect for enhanced UI components
class RoundedBorder implements Border {
    private int radius;
    private boolean hasShadow;
    private Color borderColor;
    private Color shadowColor;

    RoundedBorder(int radius) {
        this(radius, false);
    }

    RoundedBorder(int radius, boolean hasShadow) {
        this.radius = radius;
        this.hasShadow = hasShadow;
        this.borderColor = UIConstants.BORDER;
        this.shadowColor = UIConstants.SHADOW;
    }

    RoundedBorder(int radius, boolean hasShadow, Color borderColor) {
        this(radius, hasShadow);
        this.borderColor = borderColor;
    }

    public Insets getBorderInsets(Component c) {
        int shadowOffset = hasShadow ? 3 : 0;
        return new Insets(this.radius+1, this.radius+1, this.radius+2+shadowOffset, this.radius+shadowOffset);
    }

    public boolean isBorderOpaque() {
        return true;
    }

    public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        // Draw shadow if enabled
        if (hasShadow) {
            g2.setColor(shadowColor);
            for (int i = 0; i < 3; i++) {
                g2.drawRoundRect(x + i, y + i, width - 1 - i, height - 1 - i, radius, radius);
            }
        }
        
        // Draw border
        g2.setColor(borderColor);
        g2.drawRoundRect(x, y, width-1, height-1, radius, radius);
        
        g2.dispose();
    }
}

// ==================== DATA MANAGER (Singleton) ====================
class DataManager {
    private static DataManager instance;
    private List<User> users = new ArrayList<>();
    private List<Student> students = new ArrayList<>();
    private List<Subject> subjects = new ArrayList<>();
    // Map<DateString, List<AttendanceRecord>>
    private Map<String, List<AttendanceRecord>> attendanceByDate = new HashMap<>();
    private List<LeaveApplication> leaves = new ArrayList<>();
    private List<Notification> notifications = new ArrayList<>();

    private static final String DATA_DIR = "data/";
    private static final String USERS_FILE = "users.ser";
    private static final String STUDENTS_FILE = "students.ser";
    private static final String SUBJECTS_FILE = "subjects.ser";
    private static final String ATTENDANCE_FILE = "attendance.ser";
    private static final String LEAVES_FILE = "leaves.ser";
    private static final String NOTIFICATIONS_FILE = "notifications.ser";

    private DataManager() {
        createDataDirectory();
    }

    public static DataManager getInstance() {
        if (instance == null) {
            instance = new DataManager();
        }
        return instance;
    }

    private void createDataDirectory() {
        new File(DATA_DIR).mkdirs();
    }

    public void loadAllData() {
        users = loadObject(USERS_FILE);
        students = loadObject(STUDENTS_FILE);
        subjects = loadObject(SUBJECTS_FILE);
        leaves = loadObject(LEAVES_FILE);
        notifications = loadObject(NOTIFICATIONS_FILE);

        // Special handling for Map
        Object loadedAttendance = loadObjectInternal(ATTENDANCE_FILE);
        if (loadedAttendance instanceof Map) {
            attendanceByDate = (Map<String, List<AttendanceRecord>>) loadedAttendance;
        } else {
            attendanceByDate = new HashMap<>();
        }

        if (users.isEmpty()) {
            initializeSampleData();
        }
    }

    public void saveAllData() {
        saveObject(users, USERS_FILE);
        saveObject(students, STUDENTS_FILE);
        saveObject(subjects, SUBJECTS_FILE);
        saveObject(attendanceByDate, ATTENDANCE_FILE);
        saveObject(leaves, LEAVES_FILE);
        saveObject(notifications, NOTIFICATIONS_FILE);
    }

    private void saveObject(Object obj, String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(DATA_DIR + filename))) {
            oos.writeObject(obj);
        } catch (IOException e) {
            e.printStackTrace();
            // In a real app, show an error to the user
        }
    }

    @SuppressWarnings("unchecked")
    private <T> List<T> loadObject(String filename) {
        Object loaded = loadObjectInternal(filename);
        if (loaded instanceof List) {
            return (List<T>) loaded;
        }
        return new ArrayList<T>();
    }

    private Object loadObjectInternal(String filename) {
        File file = new File(DATA_DIR + filename);
        if (file.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(
                    new FileInputStream(file))) {
                return ois.readObject();
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
        return null;
    }

    private void initializeSampleData() {
        // Create admin user
        Admin admin = new Admin("A001", "admin@school.com");
        admin.setUsername("admin");
        admin.setPassword(hashPassword("admin123"));
        admin.setName("System Administrator");
        users.add(admin);

        // Create sample teacher
        Teacher teacher = new Teacher("T001", "rajesh.sharma@school.com", "CS");
        teacher.setUsername("teacher");
        teacher.setPassword(hashPassword("teacher123"));
        teacher.setName("Rajesh Sharma");
        users.add(teacher);

        // Create sample students
        Student s1 = new Student("S001", "Priya Patel", "priya.patel@school.com", "101", "CS", 1);
        s1.setUsername("priya");
        s1.setPassword(hashPassword("priya123"));
        s1.setPhone("9876543210");
        users.add(s1);
        students.add(s1);

        Student s2 = new Student("S002", "Arjun Kumar", "arjun.kumar@school.com", "102", "CS", 1);
        s2.setUsername("arjun");
        s2.setPassword(hashPassword("arjun123"));
        s2.setPhone("9876543211");
        users.add(s2);
        students.add(s2);

        // Create sample subjects
        Subject subj1 = new Subject("SUB001", "Data Structures", "CS101", "CS", 1, 75.0);
        Subject subj2 = new Subject("SUB002", "Database Systems", "CS102", "CS", 1, 75.0);
        subjects.add(subj1);
        subjects.add(subj2);

        // Enroll students
        s1.enrollInSubject(subj1.getSubjectId());
        s1.enrollInSubject(subj2.getSubjectId());
        subj1.addStudent(s1.getStudentId());
        subj2.addStudent(s1.getStudentId());

        s2.enrollInSubject(subj1.getSubjectId());
        s2.enrollInSubject(subj2.getSubjectId());
        subj1.addStudent(s2.getStudentId());
        subj2.addStudent(s2.getStudentId());

        // Sample attendance
        LocalDate today = LocalDate.now();
        Random rand = new Random();
        for (int i = 0; i < 15; i++) {
            LocalDate date = today.minusDays(i);
            List<AttendanceRecord> dayRecords = new ArrayList<>();

            for (Student s : students) {
                for (Subject subj : subjects) {
                    if(s.getEnrolledSubjects().contains(subj.getSubjectId())) {
                        AttendanceStatus status = rand.nextDouble() > 0.2 ?
                            AttendanceStatus.PRESENT : AttendanceStatus.ABSENT;
                        dayRecords.add(new AttendanceRecord(
                            s.getStudentId(), subj.getSubjectId(), date, status, "teacher"));
                    }
                }
            }
            attendanceByDate.put(date.toString(), dayRecords);
        }

        saveAllData();
    }

    public User authenticateUser(String username, String password) {
        for (User user : users) {
            if (user.getUsername().equals(username) &&
                user.authenticate(password)) {
                return user;
            }
        }
        return null;
    }

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return password; // Fallback (not recommended for production)
        }
    }

    public boolean usernameExists(String username) {
        return users.stream().anyMatch(u -> u.getUsername().equals(username));
    }

    /**
     * Adds a new user to the system and saves data.
     * Used by the Admin panel.
     */
    public void addUser(User user) {
        if (!users.contains(user)) {
            users.add(user);
            if (user instanceof Student) {
                students.add((Student) user);
            }
            saveAllData();
        }
    }

    /**
     * Removes a user from the system and saves data.
     * Used by the Admin panel.
     */
    public void removeUser(User user) {
        if (users.remove(user)) {
            if (user instanceof Student) {
                students.remove((Student) user);
            }
            // TODO: Also remove associated attendance, leaves, etc.
            saveAllData();
        }
    }

    /**
     * Generates the next available ID for a given user role.
     */
    public String getNextUserId(UserRole role) {
        String prefix = "";
        long maxId = 0;

        switch (role) {
            case ADMIN:
                prefix = "A";
                maxId = users.stream()
                    .filter(u -> u.getRole() == UserRole.ADMIN)
                    .map(u -> u.getUserId().substring(1))
                    .mapToLong(Long::parseLong)
                    .max().orElse(0);
                break;
            case TEACHER:
                prefix = "T";
                maxId = users.stream()
                    .filter(u -> u.getRole() == UserRole.TEACHER)
                    .map(u -> u.getUserId().substring(1))
                    .mapToLong(Long::parseLong)
                    .max().orElse(0);
                break;
            case STUDENT:
                prefix = "S";
                maxId = students.stream()
                    .map(s -> s.getStudentId().substring(1))
                    .mapToLong(Long::parseLong)
                    .max().orElse(0);
                break;
        }
        return prefix + String.format("%03d", maxId + 1);
    }

    // Getters
    public List<User> getUsers() { return new ArrayList<>(users); }
    public List<Student> getStudents() { return new ArrayList<>(students); }
    public List<Subject> getSubjects() { return new ArrayList<>(subjects); }
    public List<LeaveApplication> getLeaves() { return new ArrayList<>(leaves); }

    public Student getStudent(String id) {
        return students.stream().filter(s -> s.getStudentId().equals(id))
            .findFirst().orElse(null);
    }

    public Subject getSubject(String id) {
        return subjects.stream().filter(s -> s.getSubjectId().equals(id))
            .findFirst().orElse(null);
    }

    // --- CRITICAL BUG FIX ---
    /**
     * Marks attendance for a specific date AND subject.
     * This method now correctly updates records for a single subject
     * without wiping out records for other subjects on the same day.
     *
     * @param date The date of attendance
     * @param subjectId The specific subject being marked
     * @param records The list of new attendance records for this subject
     */
    public void markAttendanceForDate(LocalDate date, String subjectId, List<AttendanceRecord> records) {
        String dateKey = date.toString();
        // Get existing records for the day, or a new list
        List<AttendanceRecord> dayRecords = attendanceByDate.getOrDefault(dateKey, new ArrayList<>());

        // Remove only the old records for the *specific subject* being updated
        dayRecords.removeIf(record -> record.getSubjectId().equals(subjectId));

        // Add all the new records for this subject
        dayRecords.addAll(records);

        // Put the updated list back into the map
        attendanceByDate.put(dateKey, dayRecords);
        saveAllData();
    }

    /**
     * Incrementally adds or replaces a single attendance record for the given date.
     * This method is thread-safe and will not wipe out other subjects' records for the same day.
     * If a record for the same student & subject already exists on that date it will be replaced.
     *
     * @param date the date of the attendance
     * @param record the AttendanceRecord to add
     */
    public synchronized void addAttendanceRecord(LocalDate date, AttendanceRecord record) {
        String dateKey = date.toString();
        List<AttendanceRecord> dayRecords = attendanceByDate.getOrDefault(dateKey, new ArrayList<>());

        // Remove any existing record for same student+subject (replacement semantics)
        dayRecords.removeIf(r -> r.getStudentId().equals(record.getStudentId())
                && r.getSubjectId().equals(record.getSubjectId()));

        dayRecords.add(record);
        attendanceByDate.put(dateKey, dayRecords);
        saveAllData();
    }
    
    /**
     * Retrieves all attendance records for a specific date.
     */
    public List<AttendanceRecord> getAttendanceForDate(LocalDate date) {
        String dateKey = date.toString();
        return attendanceByDate.getOrDefault(dateKey, new ArrayList<>());
    }

    public List<AttendanceRecord> getAttendanceRecords(String studentId, String subjectId) {
        List<AttendanceRecord> result = new ArrayList<>();
        for (List<AttendanceRecord> dayRecords : attendanceByDate.values()) {
            for (AttendanceRecord record : dayRecords) {
                if ((studentId == null || record.getStudentId().equals(studentId)) &&
                    (subjectId == null || record.getSubjectId().equals(subjectId))) {
                    result.add(record);
                }
            }
        }
        return result;
    }

    public double calculateAttendancePercentage(String studentId, String subjectId) {
        List<AttendanceRecord> records = getAttendanceRecords(studentId, subjectId);
        if (records.isEmpty()) return 0.0;

        long present = records.stream()
            .filter(AttendanceRecord::isPresent)
            .count();

        return (present * 100.0) / records.size();
    }

    public void addLeave(LeaveApplication leave) {
        leaves.add(leave);
        saveAllData();
    }
}

// ==================== ENUMS ====================
enum UserRole { ADMIN, TEACHER, STUDENT }
enum AttendanceStatus { PRESENT, ABSENT, LATE }
enum LeaveType { MEDICAL, PERSONAL, EMERGENCY }
enum LeaveStatus { PENDING, APPROVED, REJECTED }
enum NotificationType { INFO, WARNING, ALERT }

// ==================== USER CLASSES ====================
abstract class User implements Serializable {
    private static final long serialVersionUID = 1L;
    protected String userId;
    protected String username;
    protected String password; // This is a hash
    protected String email;
    protected UserRole role;
    protected String name;

    public User(String userId, String email, UserRole role) {
        this.userId = userId;
        this.email = email;
        this.role = role;
    }

    public boolean authenticate(String inputPassword) {
        return DataManager.hashPassword(inputPassword).equals(password);
    }

    public abstract JFrame getDashboard();

    // Getters and setters
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public UserRole getRole() { return role; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    @Override
    public String toString() { return name + " (" + userId + ")"; }
}

class Admin extends User {
    private static final long serialVersionUID = 2L;

    public Admin(String adminId, String email) {
        super(adminId, email, UserRole.ADMIN);
    }

    @Override
    public JFrame getDashboard() {
        return new AdminDashboard(this);
    }
}

class Teacher extends User {
    private static final long serialVersionUID = 3L;
    private String department;

    public Teacher(String empId, String email, String dept) {
        super(empId, email, UserRole.TEACHER);
        this.department = dept;
    }

    @Override
    public JFrame getDashboard() {
        return new TeacherDashboard(this);
    }

    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
}

class Student extends User {
    private static final long serialVersionUID = 4L;
    private String studentId;
    private String rollNumber;
    private String phone;
    private String department;
    private int semester;
    private String simHash; // Added for Bluetooth attendance
    private List<String> enrolledSubjects = new ArrayList<>();

    public Student(String id, String name, String email, String rollNo,
                   String dept, int sem) {
        super(id, email, UserRole.STUDENT);
        this.studentId = id;
        this.name = name;
        this.rollNumber = rollNo;
        this.department = dept;
        this.semester = sem;
    }

    @Override
    public JFrame getDashboard() {
        return new StudentDashboard(this);
    }

    public void enrollInSubject(String subjectId) {
        if (!enrolledSubjects.contains(subjectId)) {
            enrolledSubjects.add(subjectId);
        }
    }

    // Getters and Setters
    public String getStudentId() { return studentId; }
    public String getRollNumber() { return rollNumber; }
    public void setRollNumber(String rollNumber) { this.rollNumber = rollNumber; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    public int getSemester() { return semester; }
    public void setSemester(int semester) { this.semester = semester; }
    public List<String> getEnrolledSubjects() { return enrolledSubjects; }
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    public String getSimHash() { return simHash; }
    public void setSimHash(String simHash) { this.simHash = simHash; }
}

/**
 * Security utilities for the Bluetooth attendance system.
 * Handles cryptographic operations and network validation.
 */
class SecurityUtils {
    private static final int SUBNET_MASK_BITS = 24; // /24 subnet

    /**
     * Generates a SHA-256 hash of the provided SIM number.
     * @param simNumber The SIM number to hash
     * @return The hex string of the hash
     */
    public static String hashSim(String simNumber) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(simNumber.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Checks if two IP addresses are in the same /24 subnet.
     * @param ip1 First IP address
     * @param ip2 Second IP address
     * @return true if both IPs are in the same subnet
     */
    public static boolean isSameNetwork(String ip1, String ip2) {
        try {
            byte[] addr1 = InetAddress.getByName(ip1).getAddress();
            byte[] addr2 = InetAddress.getByName(ip2).getAddress();
            
            // Compare first three octets for /24 subnet
            for (int i = 0; i < 3; i++) {
                if (addr1[i] != addr2[i]) return false;
            }
            return true;
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Validates an attendance packet from a student device.
     * @param packetData The raw packet data string
     * @param teacherIp The teacher's IP address
     * @return true if the packet is valid
     */
    public static boolean verifyAttendancePacket(String packetData, String teacherIp) {
        try {
            String[] parts = packetData.split("\\|");
            if (parts.length != 4) return false;

            String studentId = parts[0];
            String simHash = parts[1];
            String studentIp = parts[2];
            String biometricFlag = parts[3];

            // Verify all parts exist
            if (studentId.isEmpty() || simHash.isEmpty() || 
                studentIp.isEmpty() || biometricFlag.isEmpty()) {
                return false;
            }

            // Check biometric flag
            if (!"1".equals(biometricFlag)) return false;

            // Verify student exists and SIM hash matches
            Student student = DataManager.getInstance().getStudent(studentId);
            if (student == null || !simHash.equals(student.getSimHash())) {
                return false;
            }

            // Verify network location
            return isSameNetwork(studentIp, teacherIp);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}

// ==================== DOMAIN CLASSES ====================
class Subject implements Serializable {
    private static final long serialVersionUID = 5L;
    private String subjectId;
    private String subjectName;
    private String subjectCode;
    private String department;
    private int semester;
    private double minAttendanceRequired;
    private List<String> enrolledStudents = new ArrayList<>();

    public Subject(String id, String name, String code, String dept,
                   int sem, double minAtt) {
        this.subjectId = id;
        this.subjectName = name;
        this.subjectCode = code;
        this.department = dept;
        this.semester = sem;
        this.minAttendanceRequired = minAtt;
    }

    public void addStudent(String studentId) {
        if (!enrolledStudents.contains(studentId)) {
            enrolledStudents.add(studentId);
        }
    }

    // Getters
    public String getSubjectId() { return subjectId; }
    public String getSubjectName() { return subjectName; }
    public String getSubjectCode() { return subjectCode; }
    public List<String> getEnrolledStudents() { return enrolledStudents; }
    public String getDepartment() { return department; }
    
    @Override
    public String toString() { return subjectName + " (" + subjectCode + ")"; }
}

class AttendanceRecord implements Serializable {
    private static final long serialVersionUID = 6L;
    private String recordId;
    private String studentId;
    private String subjectId;
    private LocalDate date;
    private AttendanceStatus status;
    private String markedBy; // UserID of admin or teacher
    private LocalDateTime timestamp;

    public AttendanceRecord(String studentId, String subjectId, LocalDate date,
                           AttendanceStatus status, String markedBy) {
    this.recordId = java.util.UUID.randomUUID().toString();
        this.studentId = studentId;
        this.subjectId = subjectId;
        this.date = date;
        this.status = status;
        this.markedBy = markedBy;
        this.timestamp = LocalDateTime.now();
    }

    public boolean isPresent() {
        return status == AttendanceStatus.PRESENT || status == AttendanceStatus.LATE;
    }

    // Getters
    public String getStudentId() { return studentId; }
    public String getSubjectId() { return subjectId; }
    public LocalDate getDate() { return date; }
    public AttendanceStatus getStatus() { return status; }
    public void setStatus(AttendanceStatus status) { this.status = status; }
    public String getMarkedBy() { return markedBy; }
}

class LeaveApplication implements Serializable {
    private static final long serialVersionUID = 7L;
    private String leaveId;
    private String studentId;
    private LocalDate startDate;
    private LocalDate endDate;
    private String reason;
    private LeaveType leaveType;
    private LeaveStatus status;
    // ... other fields
    
    public LeaveApplication(String studentId, LocalDate start, LocalDate end,
                           String reason, LeaveType type) {
    this.leaveId = java.util.UUID.randomUUID().toString();
        this.studentId = studentId;
        this.startDate = start;
        this.endDate = end;
        this.reason = reason;
        this.leaveType = type;
        this.status = LeaveStatus.PENDING;
        //this.appliedDate = LocalDateTime.now(); // We can add this back if needed
    }
}

class Notification implements Serializable {
    private static final long serialVersionUID = 8L;
    // ... fields
}

// ==================== CUSTOM UI COMPONENTS ====================

/**
 * Enhanced gradient panel with smooth transitions
 */
class GradientPanel extends JPanel {
    private Color startColor;
    private Color endColor;
    private float[] gradientFractions = {0.0f, 1.0f};
    private Color[] gradientColors = new Color[2];
    private boolean useAnimatedGradient;
    private javax.swing.Timer animationTimer;
    private float gradientPosition = 0.0f;

    public GradientPanel(Color startColor, Color endColor) {
        this(startColor, endColor, false);
    }

    public GradientPanel(Color startColor, Color endColor, boolean animated) {
        this.startColor = startColor;
        this.endColor = endColor;
        this.useAnimatedGradient = animated;
        gradientColors[0] = startColor;
        gradientColors[1] = endColor;
        
        if (animated) {
            animationTimer = new javax.swing.Timer(50, e -> {
                gradientPosition += 0.02f;
                if (gradientPosition > 1.0f) gradientPosition = 0.0f;
                repaint();
            });
            animationTimer.start();
        }
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        
        int w = getWidth();
        int h = getHeight();
        
        if (useAnimatedGradient) {
            // Create animated gradient
            float x1 = w * gradientPosition;
            float y1 = 0;
            float x2 = x1 + w;
            float y2 = h;
            
            LinearGradientPaint gradient = new LinearGradientPaint(
                x1, y1, x2, y2, gradientFractions, gradientColors);
            g2d.setPaint(gradient);
        } else {
            // Standard gradient
            GradientPaint gradient = new GradientPaint(0, 0, startColor, w, h, endColor);
            g2d.setPaint(gradient);
        }
        
        g2d.fillRect(0, 0, w, h);
        g2d.dispose();
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        if (animationTimer != null) {
            animationTimer.stop();
        }
    }
}

/**
 * Enhanced ModernButton with loading state and ripple effect
 */
class ModernButton extends JButton {
    private Color backgroundColor;
    private Color hoverColor;
    private Color pressedColor;
    private int radius = 12;
    private boolean isLoading = false;
    private List<Point> ripples = new ArrayList<>();
    private List<Integer> rippleSizes = new ArrayList<>();
    private javax.swing.Timer rippleTimer;

    public ModernButton(String text) {
        super(text);
        this.backgroundColor = UIConstants.PRIMARY;
        this.hoverColor = UIConstants.PRIMARY_DARK;
        this.pressedColor = UIConstants.PRIMARY_DARK.darker();

        setForeground(Color.WHITE);
        setFont(UIConstants.BUTTON_FONT);
        setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
        setOpaque(false);
        setBorder(new RoundedBorder(12, true)); // Add shadow

        // Ripple effect
        rippleTimer = new javax.swing.Timer(10, e -> {
            for (int i = 0; i < ripples.size(); i++) {
                rippleSizes.set(i, rippleSizes.get(i) + 5);
                if (rippleSizes.get(i) > getWidth()) {
                    ripples.remove(i);
                    rippleSizes.remove(i);
                    i--;
                }
            }
            if (ripples.isEmpty()) {
                rippleTimer.stop();
            }
            repaint();
        });

        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                ripples.add(e.getPoint());
                rippleSizes.add(0);
                if (!rippleTimer.isRunning()) {
                    rippleTimer.start();
                }
            }
            
            @Override
            public void mouseEntered(MouseEvent e) {
                setBackground(UIConstants.HOVER);
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                setBackground(UIConstants.SURFACE);
            }
        });
    }

    public void setColors(Color background, Color hover, Color pressed) {
        this.backgroundColor = background;
        this.hoverColor = hover;
        this.pressedColor = pressed;
    }

    public void setLoading(boolean loading) {
        isLoading = loading;
        setEnabled(!loading);
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        // Draw background
        if (getModel().isPressed()) {
            g2.setColor(pressedColor);
        } else if (getModel().isRollover()) {
            g2.setColor(hoverColor);
        } else {
            g2.setColor(backgroundColor);
        }
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);

        // Draw ripples
        g2.setColor(new Color(255, 255, 255, 50));
        for (int i = 0; i < ripples.size(); i++) {
            Point p = ripples.get(i);
            int size = rippleSizes.get(i);
            g2.fillOval(p.x - size/2, p.y - size/2, size, size);
        }

        // Draw loading spinner or text
        if (isLoading) {
            int spinnerSize = getHeight() - 10;
            int x = (getWidth() - spinnerSize) / 2;
            int y = (getHeight() - spinnerSize) / 2;
            
            double angle = (System.currentTimeMillis() % 1000) * 360.0 / 1000.0;
            g2.rotate(Math.toRadians(angle), x + spinnerSize/2, y + spinnerSize/2);
            
            g2.setColor(Color.WHITE);
            g2.setStroke(new BasicStroke(2));
            g2.drawArc(x, y, spinnerSize, spinnerSize, 0, 270);
        } else {
            FontMetrics fm = g2.getFontMetrics(getFont());
            g2.setColor(getForeground());
            g2.setFont(getFont());
            String text = getText();
            int textX = (getWidth() - fm.stringWidth(text)) / 2;
            int textY = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
            g2.drawString(text, textX, textY);
        }

        g2.dispose();
    }
}

/**
 * A soft neumorphic-style button with subtle inner/outer shadows.
 */
class NeumorphicButton extends JButton {
    private Color base;
    private int radius = 14;

    public NeumorphicButton(String text) {
        super(text);
    base = UIConstants.SURFACE;
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
    setFont(UIConstants.BUTTON_FONT);
        setPreferredSize(new Dimension(160, 42));
    setForeground(UIConstants.TEXT_DARK);
        setCursor(new Cursor(Cursor.HAND_CURSOR));
    }

    public void setBaseColor(Color c) {
        this.base = c;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        // Outer shadow
        g2.setColor(new Color(0,0,0,20));
        g2.fillRoundRect(4, 4, w-8, h-8, radius, radius);

        // Button face
        g2.setColor(base);
        g2.fillRoundRect(0, 0, w-8, h-8, radius, radius);

        // Highlight/inner shadow
        g2.setColor(new Color(255,255,255,120));
        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.6f));
        g2.fillRoundRect(0, 0, w-8, (h-8)/2, radius, radius);

        // Text
        g2.setComposite(AlphaComposite.SrcOver);
        g2.setColor(getForeground());
        FontMetrics fm = g2.getFontMetrics(getFont());
        String text = getText();
        int tx = (w - fm.stringWidth(text)) / 2 - 4;
        int ty = (h + fm.getAscent() - fm.getDescent()) / 2 - 4;
        g2.setFont(getFont());
        g2.drawString(text, tx, ty);

        g2.dispose();
    }
}

/**
 * GlassPanel: translucent rounded panel for glassmorphism effect.
 */
class GlassPanel extends JPanel {
    private int arc = 20;
    private Color glass = new Color(255, 255, 255, 245); // More opaque for better contrast

    public GlassPanel() {
        setOpaque(false);
        setBackground(Color.WHITE);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        // Soft shadow
        g2.setColor(new Color(0,0,0,30));
        g2.fillRoundRect(6, 6, w-12, h-12, arc, arc);

        // Glassy panel
        g2.setColor(glass);
        g2.fillRoundRect(0, 0, w-12, h-12, arc, arc);
        g2.dispose();

        super.paintComponent(g);
    }
}

/**
 * CardPanel wraps content in a rounded translucent card with padding.
 */
class CardPanel extends JPanel {
    private int arc = 16;
    private Color bg = Color.WHITE;

    public CardPanel(Component content) {
        setLayout(new BorderLayout());
        setOpaque(true);
        setBackground(Color.WHITE);
        JPanel inner = new JPanel(new BorderLayout());
        inner.setOpaque(true);
        inner.setBackground(Color.WHITE);
        inner.add(content, BorderLayout.CENTER);
        inner.setBorder(BorderFactory.createEmptyBorder(12,12,12,12));
        add(inner, BorderLayout.CENTER);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth();
        int h = getHeight();

        // subtle shadow
        g2.setColor(new Color(0,0,0,30));
        g2.fillRoundRect(4, 6, w-8, h-8, arc, arc);

        // card background
        g2.setColor(bg);
        g2.fillRoundRect(0, 0, w-8, h-8, arc, arc);
        g2.dispose();

        super.paintComponent(g);
    }
}

/**
 * A modern text field with a rounded border and placeholder text.
 */
class ModernTextField extends JTextField {
    private int radius = 12;
    private String placeholder = "";

    public ModernTextField(int columns) {
        super(columns);
        setOpaque(true);
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        setFont(UIConstants.BODY_FONT);
        setForeground(Color.BLACK);
        setBorder(new RoundedBorder(12, true)); // Add shadow
        setCursor(new Cursor(Cursor.TEXT_CURSOR));
    }

    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        // Paint background
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
        
        // Paint placeholder text
        if (getText().isEmpty() && !placeholder.isEmpty()) {
            g2.setColor(UIConstants.TEXT_LIGHT);
            g2.setFont(getFont().deriveFont(Font.ITALIC));
            FontMetrics fm = g2.getFontMetrics();
            int y = (getHeight() - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(placeholder, getInsets().left, y);
        }
        
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    protected void paintBorder(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        if (hasFocus()) {
            g2.setColor(UIConstants.PRIMARY);
            g2.setStroke(new BasicStroke(2));
        } else {
            g2.setColor(UIConstants.BORDER);
            g2.setStroke(new BasicStroke(1));
        }
        
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
        g2.dispose();
    }
}

/**
 * A modern password field, consistent with ModernTextField.
 */
class ModernPasswordField extends JPasswordField {
    private int radius = 12;
    private String placeholder = "";

    public ModernPasswordField(int columns) {
        super(columns);
        setOpaque(true);
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));
        setFont(UIConstants.BODY_FONT);
        setForeground(Color.BLACK);
        setBorder(new RoundedBorder(12, true)); // Add shadow
        setCursor(new Cursor(Cursor.TEXT_CURSOR));
    }
    
    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
        
        // Paint placeholder text
        if (getPassword().length == 0 && !placeholder.isEmpty()) {
            g2.setColor(UIConstants.TEXT_LIGHT);
            g2.setFont(getFont().deriveFont(Font.ITALIC));
            FontMetrics fm = g2.getFontMetrics();
            int y = (getHeight() - fm.getHeight()) / 2 + fm.getAscent();
            g2.drawString(placeholder, getInsets().left, y);
        }
        
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    protected void paintBorder(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        if (hasFocus()) {
            g2.setColor(UIConstants.PRIMARY);
            g2.setStroke(new BasicStroke(2));
        } else {
            g2.setColor(UIConstants.BORDER);
            g2.setStroke(new BasicStroke(1));
        }
        
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
        g2.dispose();
    }
}

/**
 * Enhanced circular progress bar with smooth animation and gradient effects
 */
class CircularProgressBar extends JComponent {
    private double value = 0.0; // 0.0 to 100.0
    private double animatedValue = 0.0;
    private Color progressColor = UIConstants.SUCCESS;
    private javax.swing.Timer animationTimer;
    private boolean isHovered = false;
    private float glowIntensity = 0.0f;
    private javax.swing.Timer glowTimer;
    
    public CircularProgressBar() {
        setPreferredSize(new Dimension(100, 100));
        setupAnimation();
        setupHoverEffect();
    }

    private void setupAnimation() {
        animationTimer = new javax.swing.Timer(16, e -> {
            double diff = value - animatedValue;
            if (Math.abs(diff) > 0.1) {
                animatedValue += diff * 0.1;
                updateProgressColor();
                repaint();
            } else {
                animatedValue = value;
                updateProgressColor();
                ((javax.swing.Timer)e.getSource()).stop();
            }
        });
    }

    private void setupHoverEffect() {
        glowTimer = new javax.swing.Timer(50, e -> {
            if (isHovered && glowIntensity < 1.0f) {
                glowIntensity = Math.min(1.0f, glowIntensity + 0.1f);
                repaint();
            } else if (!isHovered && glowIntensity > 0.0f) {
                glowIntensity = Math.max(0.0f, glowIntensity - 0.1f);
                repaint();
            } else {
                ((javax.swing.Timer)e.getSource()).stop();
            }
        });

        addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                isHovered = true;
                if (!glowTimer.isRunning()) glowTimer.start();
            }
            public void mouseExited(MouseEvent e) {
                isHovered = false;
                if (!glowTimer.isRunning()) glowTimer.start();
            }
        });
    }

    private void updateProgressColor() {
        if (animatedValue >= 75) {
            progressColor = UIConstants.SUCCESS;
        } else if (animatedValue >= 60) {
            progressColor = UIConstants.WARNING;
        } else {
            progressColor = UIConstants.ERROR;
        }
    }

    public void setValue(double value) {
        if (this.value != value) {
            this.value = value;
            if (!animationTimer.isRunning()) {
                animationTimer.start();
            }
        }
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

        int padding = 10;
        int size = Math.min(getWidth(), getHeight()) - (padding * 2);
        int x = (getWidth() - size) / 2;
        int y = (getHeight() - size) / 2;
        int strokeWidth = 12;

        // Draw glow effect when hovered
        if (glowIntensity > 0) {
            int glowSize = 20;
            Color glowColor = new Color(
                progressColor.getRed(),
                progressColor.getGreen(),
                progressColor.getBlue(),
                (int)(50 * glowIntensity)
            );
            g2.setColor(glowColor);
            g2.setStroke(new BasicStroke(strokeWidth + glowSize));
            int angle = (int) (animatedValue * 3.6);
            g2.drawArc(x - glowSize/2, y - glowSize/2, 
                      size + glowSize, size + glowSize, 
                      90, -angle);
        }

        // Draw outer shadow
        g2.setColor(new Color(0, 0, 0, 20));
        g2.fillOval(x + 2, y + 2, size, size);

        // Draw background track with gradient
        g2.setStroke(new BasicStroke(strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        Paint trackGradient = new LinearGradientPaint(
            x, y, x + size, y + size,
            new float[]{0f, 1f},
            new Color[]{
                new Color(UIConstants.BORDER.getRed(),
                         UIConstants.BORDER.getGreen(),
                         UIConstants.BORDER.getBlue(),
                         50),
                UIConstants.BORDER
            }
        );
        g2.setPaint(trackGradient);
        g2.drawArc(x, y, size, size, 0, 360);

        // Draw progress arc with gradient
        Paint progressGradient = new LinearGradientPaint(
            x, y, x + size, y + size,
            new float[]{0f, 1f},
            new Color[]{progressColor, progressColor.brighter()}
        );
        g2.setPaint(progressGradient);
        int angle = (int) (animatedValue * 3.6);
        g2.drawArc(x, y, size, size, 90, -angle);

        // Draw percentage text with shadow
        String text = String.format("%.0f%%", animatedValue);
        g2.setFont(UIConstants.SUBTITLE_FONT);
        FontMetrics fm = g2.getFontMetrics();
        int textX = (getWidth() - fm.stringWidth(text)) / 2;
        int textY = (getHeight() - fm.getHeight()) / 2 + fm.getAscent();

        // Draw text shadow
        g2.setColor(new Color(0, 0, 0, 30));
        g2.drawString(text, textX + 1, textY + 1);

        // Draw actual text
        g2.setColor(UIConstants.TEXT_DARK);
        g2.drawString(text, textX, textY);

        // Draw small label below percentage
        String label = getStatusLabel(animatedValue);
        g2.setFont(UIConstants.BODY_FONT);
        fm = g2.getFontMetrics();
        textX = (getWidth() - fm.stringWidth(label)) / 2;
        textY += fm.getHeight();
        g2.setColor(progressColor);
        g2.drawString(label, textX, textY);

        g2.dispose();
    }

    private String getStatusLabel(double value) {
        if (value >= 75) return "Good";
        if (value >= 60) return "Warning";
        return "Low";
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        if (animationTimer != null) {
            animationTimer.stop();
        }
        if (glowTimer != null) {
            glowTimer.stop();
        }
    }
}

/**
 * A custom icon for the student subject cards.
 */
class SubjectCardIcon implements Icon {
    private int width = 32;
    private int height = 32;

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setStroke(new BasicStroke(2));
        
        // Draw a simple open book icon
        g2.setColor(UIConstants.PRIMARY);
        g2.fillRoundRect(x, y + 4, width, height - 8, 8, 8);
        
        g2.setColor(Color.WHITE);
        g2.drawLine(x + (width / 2), y + 6, x + (width / 2), y + height - 10);
        
        g2.setColor(UIConstants.PRIMARY.darker());
        g2.drawRoundRect(x, y + 4, width, height - 8, 8, 8);
        
        g2.dispose();
    }

    @Override
    public int getIconWidth() { return width; }
    @Override
    public int getIconHeight() { return height; }
}


// ==================== LOGIN FRAME (Redesigned) ====================
class LoginFrame extends JFrame {
    private ModernTextField usernameField;
    private ModernPasswordField passwordField;
    private CardLayout cardLayout;
    private JPanel roleCardPanel;

    public LoginFrame() {
        setTitle("Smart Attendance System");
        setSize(1000, 700);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(true);
        setMinimumSize(new Dimension(800, 600));
        
        initComponents();
        setVisible(true);
    }

    private void initComponents() {
        // Main split layout
        JPanel mainPanel = new JPanel(new GridLayout(1, 2));
        mainPanel.setBackground(UIConstants.BACKGROUND);

        // Left Panel - Branding & Graphics
        JPanel brandPanel = new GradientPanel(UIConstants.PRIMARY, UIConstants.PRIMARY_DARK, true) {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                // Draw decorative circles
                g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.1f));
                g2.setColor(Color.WHITE);
                g2.fillOval(-50, -50, 200, 200);
                g2.fillOval(getWidth() - 100, getHeight() - 100, 300, 300);
                g2.dispose();
            }
        };
        brandPanel.setLayout(new GridBagLayout());
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(0, 40, 10, 40);
        
        // Brand Icon
        JLabel iconLabel = new JLabel("✓");
        iconLabel.setFont(new Font("Segoe UI Symbol", Font.BOLD, 72));
        iconLabel.setForeground(Color.WHITE);
        brandPanel.add(iconLabel, gbc);

        gbc.gridy = 1;
        JLabel titleLabel = new JLabel("Smart Attendance");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 36));
        titleLabel.setForeground(Color.WHITE);
        brandPanel.add(titleLabel, gbc);

        gbc.gridy = 2;
        JLabel subtitleLabel = new JLabel("System");
        subtitleLabel.setFont(new Font("Segoe UI", Font.BOLD, 32));
        subtitleLabel.setForeground(new Color(255, 255, 255, 220));
        brandPanel.add(subtitleLabel, gbc);

        // Right Panel - Login Form
        JPanel loginPanel = new JPanel(new GridBagLayout());
        loginPanel.setBackground(UIConstants.BACKGROUND);
        
        // Wrap form in a glass card
        JPanel formCard = new GlassPanel();
        formCard.setLayout(new BorderLayout(20, 20));
        formCard.setBorder(BorderFactory.createEmptyBorder(40, 40, 40, 40));
        formCard.setPreferredSize(new Dimension(450, 600));
        
        // Form Content
        JPanel formContent = new JPanel(new GridBagLayout());
        formContent.setOpaque(false);
        
        gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 20, 0);
        
        // Welcome text
        gbc.gridy = 0;
        JLabel welcomeLabel = new JLabel("Welcome Back");
        welcomeLabel.setFont(UIConstants.TITLE_FONT);
        welcomeLabel.setForeground(UIConstants.TEXT_DARK);
        formContent.add(welcomeLabel, gbc);
        
        gbc.gridy = 1;
        JLabel loginLabel = new JLabel("Sign in to continue");
        loginLabel.setFont(UIConstants.SUBTITLE_FONT);
        loginLabel.setForeground(UIConstants.TEXT_MEDIUM);
        formContent.add(loginLabel, gbc);

        // Role selector cards
        gbc.gridy = 2;
        gbc.insets = new Insets(20, 0, 30, 0);
        cardLayout = new CardLayout();
        roleCardPanel = new JPanel(cardLayout);
        roleCardPanel.setOpaque(false);
        
        // Create role cards
        String[] roles = {"Admin", "Teacher", "Student"};
        JPanel roleCards = new JPanel(new GridLayout(1, 3, 10, 0));
        roleCards.setOpaque(false);
        
        for (String role : roles) {
            JPanel card = new JPanel();
            card.setLayout(new BorderLayout());
            card.setBackground(UIConstants.SURFACE);
            card.setBorder(BorderFactory.createCompoundBorder(
                new RoundedBorder(8),
                BorderFactory.createEmptyBorder(15, 15, 15, 15)
            ));
            card.setCursor(new Cursor(Cursor.HAND_CURSOR));
            
            JLabel roleIcon = new JLabel(getRoleIcon(role), SwingConstants.CENTER);
            JLabel roleLabel = new JLabel(role, SwingConstants.CENTER);
            roleLabel.setFont(UIConstants.BODY_FONT);
            roleLabel.setForeground(UIConstants.TEXT_DARK);
            
            card.add(roleIcon, BorderLayout.CENTER);
            card.add(roleLabel, BorderLayout.SOUTH);
            
            card.addMouseListener(new MouseAdapter() {
                public void mouseEntered(MouseEvent e) {
                    card.setBackground(UIConstants.PRIMARY_LIGHT);
                }
                public void mouseExited(MouseEvent e) {
                    card.setBackground(UIConstants.SURFACE);
                }
                public void mouseClicked(MouseEvent e) {
                    // Visual feedback
                    card.setBackground(UIConstants.PRIMARY_LIGHT);
                }
            });
            
            roleCards.add(card);
        }
        formContent.add(roleCards, gbc);

        // Username field
        gbc.gridy = 3;
        gbc.insets = new Insets(0, 0, 20, 0);
        JLabel userLabel = new JLabel("Username");
        userLabel.setFont(UIConstants.BODY_BOLD_FONT);
        userLabel.setForeground(UIConstants.TEXT_DARK);
        formContent.add(userLabel, gbc);

        gbc.gridy = 4;
        gbc.insets = new Insets(0, 0, 25, 0);
        usernameField = new ModernTextField(20);
        usernameField.setPlaceholder("Enter your username");
        formContent.add(usernameField, gbc);

        // Password field
        gbc.gridy = 5;
        gbc.insets = new Insets(0, 0, 20, 0);
        JLabel passLabel = new JLabel("Password");
        passLabel.setFont(UIConstants.BODY_BOLD_FONT);
        passLabel.setForeground(UIConstants.TEXT_DARK);
        formContent.add(passLabel, gbc);

        gbc.gridy = 6;
        gbc.insets = new Insets(0, 0, 30, 0);
        passwordField = new ModernPasswordField(20);
        passwordField.setPlaceholder("Enter your password");
        passwordField.addActionListener(e -> handleLogin());
        formContent.add(passwordField, gbc);

        // Login button
        gbc.gridy = 7;
        gbc.insets = new Insets(0, 0, 30, 0);
        ModernButton loginButton = new ModernButton("Sign In");
        loginButton.setPreferredSize(new Dimension(380, 50));
        loginButton.addActionListener(e -> handleLogin());
        formContent.add(loginButton, gbc);

        // Demo credentials
        gbc.gridy = 8;
        JLabel infoLabel = new JLabel("<html><div style='text-align: center; color: #666;'>" +
            "<b>Demo Credentials</b><br>" +
            "Admin: admin / admin123<br>" +
            "Teacher: teacher / teacher123<br>" +
            "Student: priya / priya123" +
            "</div></html>");
        infoLabel.setFont(UIConstants.CAPTION_FONT);
        infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
        formContent.add(infoLabel, gbc);

        formCard.add(formContent, BorderLayout.CENTER);
        loginPanel.add(formCard);

        // Add panels to main split
        mainPanel.add(brandPanel);
        mainPanel.add(loginPanel);

        // Add to frame
        setContentPane(mainPanel);
    }

    private String getRoleIcon(String role) {
        switch (role) {
            case "Admin": return "👑";
            case "Teacher": return "👩‍🏫";
            case "Student": return "👨‍🎓";
            default: return "👤";
        }
    }

    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (username.isEmpty() || password.isEmpty()) {
            showModernDialog("Error", "Please enter username and password", JOptionPane.ERROR_MESSAGE);
            return;
        }

        User user = DataManager.getInstance().authenticateUser(username, password);

        if (user != null) {
            dispose();
            user.getDashboard(); // Polymorphically opens the correct dashboard
        } else {
            showModernDialog("Login Failed", "Invalid username or password", JOptionPane.ERROR_MESSAGE);
            passwordField.setText("");
        }
    }

    private void showModernDialog(String title, String message, int messageType) {
        JOptionPane.showMessageDialog(this, message, title, messageType);
    }
}

// ==================== REGISTRATION FRAME (Now an Admin Tool) ====================
/**
 * This is now a JDialog launched from the Admin Panel to add ANY user.
 * It dynamically changes based on the selected role.
 */
class AddUserDialog extends JDialog {
    private AdminUserManagementPanel parentPanel; // To refresh table on success
    
    private ModernTextField nameField, emailField, usernameField;
    private ModernPasswordField passwordField;
    private JComboBox<UserRole> roleCombo;

    // Panels for different roles
    private JPanel cardsPanel;
    private CardLayout cardLayout;
    private JPanel studentPanel;
    private JPanel teacherPanel;

    // Student fields
    private ModernTextField rollNoField, phoneField;
    private JComboBox<String> studentDeptCombo;
    private JComboBox<Integer> semesterCombo;
    
    // Teacher fields
    private JComboBox<String> teacherDeptCombo;
    
    private final String[] DEPARTMENTS = {"CS", "IT", "ECE", "EEE", "ME", "CE"};
    private final Integer[] SEMESTERS = {1, 2, 3, 4, 5, 6, 7, 8};

    public AddUserDialog(JFrame parent, AdminUserManagementPanel parentPanel) {
        super(parent, "Add New User", true);
        this.parentPanel = parentPanel;
        setSize(500, 650);
        setLocationRelativeTo(parent);
        setResizable(false);
        
        initComponents();
        setVisible(true);
    }

    private void initComponents() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(Color.WHITE);

        // Header with gradient effect
        JPanel headerPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                // Create gradient
                GradientPaint gradient = new GradientPaint(
                    0, 0, UIConstants.PRIMARY,
                    getWidth(), getHeight(), UIConstants.PRIMARY_DARK);
                g2.setPaint(gradient);
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.dispose();
            }
        };
        headerPanel.setPreferredSize(new Dimension(500, 80));
        headerPanel.setLayout(new GridBagLayout());

        JLabel titleLabel = new JLabel("Create New User Account");
        titleLabel.setFont(UIConstants.TITLE_FONT);
        titleLabel.setForeground(Color.WHITE);
        headerPanel.add(titleLabel);

        // Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(Color.WHITE);
        formPanel.setBorder(BorderFactory.createEmptyBorder(20, 40, 20, 40));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 0, 8, 0);
        gbc.gridx = 0;
        gbc.weightx = 1.0;

        // Full Name
        gbc.gridy = 0;
        formPanel.add(createLabel("Full Name"), gbc);
        gbc.gridy = 1;
        nameField = new ModernTextField(20);
        formPanel.add(nameField, gbc);

        // Email
        gbc.gridy = 2;
        formPanel.add(createLabel("Email"), gbc);
        gbc.gridy = 3;
        emailField = new ModernTextField(20);
        formPanel.add(emailField, gbc);

        // Username
        gbc.gridy = 4;
        formPanel.add(createLabel("Username"), gbc);
        gbc.gridy = 5;
        usernameField = new ModernTextField(20);
        formPanel.add(usernameField, gbc);

        // Password
        gbc.gridy = 6;
        formPanel.add(createLabel("Password"), gbc);
        gbc.gridy = 7;
        passwordField = new ModernPasswordField(20);
        formPanel.add(passwordField, gbc);

        // Role
        gbc.gridy = 8;
        formPanel.add(createLabel("User Role"), gbc);
        gbc.gridy = 9;
        roleCombo = new JComboBox<>(UserRole.values());
        roleCombo.setFont(UIConstants.BODY_FONT);
        roleCombo.setPreferredSize(new Dimension(300, 40));
        formPanel.add(roleCombo, gbc);
        
        // --- Dynamic Role Panels ---
        cardLayout = new CardLayout();
        cardsPanel = new JPanel(cardLayout);
        cardsPanel.setOpaque(false);
        
        // Student Panel
        studentPanel = createStudentPanel();
        cardsPanel.add(studentPanel, UserRole.STUDENT.toString());
        
        // Teacher Panel
        teacherPanel = createTeacherPanel();
        cardsPanel.add(teacherPanel, UserRole.TEACHER.toString());
        
        // Admin Panel (empty)
        JPanel adminPanel = new JPanel();
        adminPanel.setOpaque(false);
        cardsPanel.add(adminPanel, UserRole.ADMIN.toString());
        
        gbc.gridy = 10;
        gbc.insets = new Insets(15, -40, 0, -40); // Span full width
        formPanel.add(cardsPanel, gbc);
        
        // Show student panel by default
        cardLayout.show(cardsPanel, UserRole.STUDENT.toString());
        roleCombo.setSelectedItem(UserRole.STUDENT);
        
        roleCombo.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                cardLayout.show(cardsPanel, e.getItem().toString());
            }
        });

        // Buttons
        gbc.gridy = 11;
        gbc.insets = new Insets(20, 0, 10, 0);
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.setBackground(Color.WHITE);

        NeumorphicButton createBtn = new NeumorphicButton("Create User");
        createBtn.setPreferredSize(new Dimension(150, 40));
        createBtn.addActionListener(e -> handleCreation());

        NeumorphicButton cancelBtn = new NeumorphicButton("Cancel");
        cancelBtn.setPreferredSize(new Dimension(130, 40));
        cancelBtn.setBaseColor(UIConstants.TEXT_LIGHT);
        cancelBtn.addActionListener(e -> dispose());
        
        buttonPanel.add(createBtn);
        buttonPanel.add(cancelBtn);
        formPanel.add(buttonPanel, gbc);

        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(formPanel), BorderLayout.CENTER);

        add(mainPanel);
    }
    
    private JPanel createStudentPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(UIConstants.BORDER), 
            "Student Details", TitledBorder.LEFT, TitledBorder.TOP,
            UIConstants.HEADER_FONT, UIConstants.PRIMARY
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 20, 8, 20);
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        
        gbc.gridy = 0;
        panel.add(createLabel("Roll Number"), gbc);
        gbc.gridy = 1;
        rollNoField = new ModernTextField(20);
        panel.add(rollNoField, gbc);
        
        gbc.gridy = 2;
        panel.add(createLabel("Phone"), gbc);
        gbc.gridy = 3;
        phoneField = new ModernTextField(20);
        panel.add(phoneField, gbc);
        
        gbc.gridy = 4;
        panel.add(createLabel("Department"), gbc);
        gbc.gridy = 5;
        studentDeptCombo = new JComboBox<>(DEPARTMENTS);
        studentDeptCombo.setPreferredSize(new Dimension(300, 40));
        panel.add(studentDeptCombo, gbc);
        
        gbc.gridy = 6;
        panel.add(createLabel("Semester"), gbc);
        gbc.gridy = 7;
        semesterCombo = new JComboBox<>(SEMESTERS);
        semesterCombo.setPreferredSize(new Dimension(300, 40));
        panel.add(semesterCombo, gbc);
        
        return panel;
    }
    
    private JPanel createTeacherPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setOpaque(false);
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(UIConstants.BORDER), 
            "Teacher Details", TitledBorder.LEFT, TitledBorder.TOP,
            UIConstants.HEADER_FONT, UIConstants.PRIMARY
        ));
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 20, 8, 20);
        gbc.gridx = 0;
        gbc.weightx = 1.0;

        gbc.gridy = 0;
        panel.add(createLabel("Department"), gbc);
        gbc.gridy = 1;
        teacherDeptCombo = new JComboBox<>(DEPARTMENTS);
        teacherDeptCombo.setPreferredSize(new Dimension(300, 40));
        panel.add(teacherDeptCombo, gbc);
        
        return panel;
    }

    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(UIConstants.BUTTON_FONT);
        label.setForeground(UIConstants.TEXT_DARK);
        return label;
    }

    private void handleCreation() {
        String name = nameField.getText().trim();
        String email = emailField.getText().trim();
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        UserRole role = (UserRole) roleCombo.getSelectedItem();

        if (name.isEmpty() || email.isEmpty() || username.isEmpty() || password.isEmpty()) {
            showError("Please fill all common fields.");
            return;
        }

        if (DataManager.getInstance().usernameExists(username)) {
            showError("Username already exists. Please choose another.");
            return;
        }
        
        String hashedPassword = DataManager.hashPassword(password);
        User newUser = null;
        String userId = DataManager.getInstance().getNextUserId(role);
        
        try {
            switch (role) {
                case ADMIN:
                    Admin admin = new Admin(userId, email);
                    newUser = admin;
                    break;
                    
                case TEACHER:
                    String teacherDept = (String) teacherDeptCombo.getSelectedItem();
                    Teacher teacher = new Teacher(userId, email, teacherDept);
                    teacher.setDepartment(teacherDept);
                    newUser = teacher;
                    break;
                    
                case STUDENT:
                    String rollNo = rollNoField.getText().trim();
                    String phone = phoneField.getText().trim();
                    String studentDept = (String) studentDeptCombo.getSelectedItem();
                    int semester = (Integer) semesterCombo.getSelectedItem();
                    
                    if (rollNo.isEmpty() || phone.isEmpty()) {
                        showError("Please fill all student details.");
                        return;
                    }
                    
                    Student student = new Student(userId, name, email, rollNo, studentDept, semester);
                    student.setPhone(phone);
                    
                    // Auto-enroll student in subjects for their dept/semester
                    for (Subject subject : DataManager.getInstance().getSubjects()) {
                        if (subject.getDepartment().equals(studentDept)) {
                            student.enrollInSubject(subject.getSubjectId());
                            subject.addStudent(student.getStudentId());
                        }
                    }
                    newUser = student;
                    break;
            }

            if (newUser != null) {
                newUser.setName(name);
                newUser.setUsername(username);
                newUser.setPassword(hashedPassword);
                
                DataManager.getInstance().addUser(newUser);
                
                JOptionPane.showMessageDialog(this, 
                    role.toString() + " user created successfully!", 
                    "Success", JOptionPane.INFORMATION_MESSAGE);
                
                parentPanel.loadUsers(); // Refresh the admin table
                dispose();
            }
        } catch (Exception e) {
            e.printStackTrace();
            showError("An error occurred: " + e.getMessage());
        }
    }
    
    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }
}

// ==================== BASE DASHBOARD FRAME ====================
/**
 * A base dashboard frame to remove code duplication from
 * Admin, Teacher, and Student dashboards.
 */
abstract class BaseDashboardFrame extends JFrame {
    protected User currentUser;
    protected JPanel contentPanel;
    protected CardLayout cardLayout;
    
    public BaseDashboardFrame(User user) {
        this.currentUser = user;
        setTitle("Smart Attendance System - " + user.getName());
        setSize(1200, 750);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());
    }
    
    protected void initComponents(String title, JPanel sidebar) {
        // Header
        JPanel headerPanel = new JPanel();
        headerPanel.setBackground(UIConstants.PRIMARY);
        headerPanel.setPreferredSize(new Dimension(1200, 70));
        headerPanel.setLayout(new BorderLayout());
        
        JLabel titleLabel = new JLabel("   " + title + " - " + currentUser.getName());
        titleLabel.setFont(UIConstants.TITLE_FONT);
        titleLabel.setForeground(Color.WHITE);
        
        NeumorphicButton logoutBtn = new NeumorphicButton("Logout");
        logoutBtn.setPreferredSize(new Dimension(100, 35));
        logoutBtn.setBaseColor(UIConstants.ERROR_LIGHT);
        logoutBtn.setForeground(UIConstants.ERROR_DARK);
        logoutBtn.addActionListener(e -> logout());
        
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 18));
        rightPanel.setOpaque(false);
        rightPanel.add(logoutBtn);
        
        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(rightPanel, BorderLayout.EAST);
        
        // Content Panel
        cardLayout = new CardLayout();
        contentPanel = new JPanel(cardLayout);
        contentPanel.setBackground(Color.WHITE);
        
        add(headerPanel, BorderLayout.NORTH);
        add(sidebar, BorderLayout.WEST);
        add(contentPanel, BorderLayout.CENTER);
    }
    
    protected JButton createMenuButton(String text, String icon, String cardName) {
        JButton btn = new JButton("  " + icon + "    " + text);
        btn.setMaximumSize(new Dimension(210, 50));
        btn.setAlignmentX(Component.CENTER_ALIGNMENT);
        btn.setBackground(UIConstants.BACKGROUND);
        btn.setForeground(UIConstants.TEXT_DARK);
        btn.setFont(UIConstants.BUTTON_FONT);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createEmptyBorder(10, 25, 10, 10));

        // Use a persistent border to show selection
        Border emptyBorder = BorderFactory.createEmptyBorder(0, 5, 0, 0);
        Border activeBorder = BorderFactory.createMatteBorder(0, 5, 0, 0, UIConstants.PRIMARY);
        btn.setBorder(emptyBorder);
        
        btn.addActionListener(e -> {
            cardLayout.show(contentPanel, cardName);
            // Reset all buttons in this sidebar
            Container parent = btn.getParent();
            for (Component c : parent.getComponents()) {
                if (c instanceof JButton) {
                    ((JButton)c).setBorder(emptyBorder);
                    c.setBackground(UIConstants.BACKGROUND);
                    c.setForeground(UIConstants.TEXT_DARK);
                }
            }
            // Highlight this button
            btn.setBorder(activeBorder);
            btn.setBackground(Color.WHITE);
            btn.setForeground(UIConstants.PRIMARY);
        });
        
        btn.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                if(btn.getBorder() == emptyBorder) { // Don't change bg if selected
                    btn.setBackground(new Color(235, 238, 241));
                }
            }
            public void mouseExited(MouseEvent e) {
                if(btn.getBorder() == emptyBorder) {
                    btn.setBackground(UIConstants.BACKGROUND);
                }
            }
        });
        
        return btn;
    }
    
    private void logout() {
        int choice = JOptionPane.showConfirmDialog(this, 
            "Are you sure you want to logout?", "Logout",
            JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        
        if (choice == JOptionPane.YES_OPTION) {
            DataManager.getInstance().saveAllData();
            dispose();
            new LoginFrame();
        }
    }
}

// ==================== ADMIN DASHBOARD (Redesigned) ====================
class AdminDashboard extends BaseDashboardFrame {
    public AdminDashboard(Admin admin) {
        super(admin);
        
        JPanel sidebar = createSidebar();
        initComponents("ADMIN DASHBOARD", sidebar);
        
        contentPanel.add(new AdminOverviewPanel(), "Overview");
        contentPanel.add(new AdminUserManagementPanel(), "Manage Users");
        contentPanel.add(new AdminAttendancePanel(admin), "Manage Attendance"); // New Panel
        contentPanel.add(new AdminReportPanel(), "System Reports");
        
        // Set default view
        cardLayout.show(contentPanel, "Overview");
        // Highlight first button
        ((JButton)sidebar.getComponent(1)).doClick();
        
        setVisible(true);
    }
    
    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(UIConstants.BACKGROUND);
        sidebar.setPreferredSize(new Dimension(230, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UIConstants.BORDER));
        
        sidebar.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // 
        sidebar.add(createMenuButton("Overview", "📊", "Overview"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("Manage Users", "👥", "Manage Users"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("Manage Attendance", "✎", "Manage Attendance"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("System Reports", "📈", "System Reports"));
        
        sidebar.add(Box.createVerticalGlue());
        
        return sidebar;
    }
}

// --- Admin Panels ---
class AdminOverviewPanel extends JPanel {
    public AdminOverviewPanel() {
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        
        JLabel title = new JLabel("System Overview");
        title.setFont(UIConstants.TITLE_FONT);
        title.setForeground(UIConstants.TEXT_DARK);
        
        JPanel statsPanel = new JPanel(new GridLayout(1, 4, 25, 25));
        statsPanel.setBackground(Color.WHITE);
        statsPanel.setBorder(BorderFactory.createEmptyBorder(30, 0, 0, 0));
        
        statsPanel.add(createStatCard("Total Users",
            String.valueOf(DataManager.getInstance().getUsers().size()),
            UIConstants.PRIMARY));
        statsPanel.add(createStatCard("Students",
            String.valueOf(DataManager.getInstance().getStudents().size()),
            UIConstants.SUCCESS));
        statsPanel.add(createStatCard("Subjects",
            String.valueOf(DataManager.getInstance().getSubjects().size()),
            UIConstants.WARNING));
        statsPanel.add(createStatCard("Teachers",
            String.valueOf(DataManager.getInstance().getUsers().stream()
                .filter(u -> u.getRole() == UserRole.TEACHER).count()),
            new Color(23, 162, 184)));
        
        add(title, BorderLayout.NORTH);
        add(statsPanel, BorderLayout.CENTER);
    }
    
    private JPanel createStatCard(String label, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(color.brighter().brighter());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(5, 0, 0, 0, color),
            BorderFactory.createEmptyBorder(20, 25, 20, 25)
        ));
        
        JLabel valueLabel = new JLabel(value);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 42));
        valueLabel.setForeground(color.darker());
        
        JLabel labelText = new JLabel(label);
        labelText.setFont(UIConstants.HEADER_FONT);
        labelText.setForeground(UIConstants.TEXT_LIGHT);
        
        card.add(valueLabel, BorderLayout.NORTH);
        card.add(labelText, BorderLayout.SOUTH);
        
        return card;
    }
}

class AdminUserManagementPanel extends JPanel {
    private JTable userTable;
    private DefaultTableModel tableModel;
    private List<User> allUsers;
    
    public AdminUserManagementPanel() {
        setLayout(new BorderLayout(20, 20));
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        
        JLabel title = new JLabel("User Management");
        title.setFont(UIConstants.TITLE_FONT);
        add(title, BorderLayout.NORTH);
        
        // Table
        String[] columns = {"User ID", "Name", "Username", "Role", "Email"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        userTable = new JTable(tableModel);
        setupTableStyle(userTable);
        
        loadUsers();
        
    JScrollPane scrollPane = new JScrollPane(userTable);
    scrollPane.setBorder(BorderFactory.createLineBorder(UIConstants.BORDER));
    add(new CardPanel(scrollPane), BorderLayout.CENTER);
        
        // Button Panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(Color.WHITE);
        
        NeumorphicButton addUserBtn = new NeumorphicButton("＋ Add User");
        addUserBtn.setPreferredSize(new Dimension(140, 40));
        addUserBtn.setBaseColor(UIConstants.SUCCESS_LIGHT);
        addUserBtn.setForeground(UIConstants.SUCCESS_DARK);
        addUserBtn.addActionListener(e -> openAddUserDialog());
        
        NeumorphicButton removeUserBtn = new NeumorphicButton("− Remove User");
        removeUserBtn.setPreferredSize(new Dimension(160, 40));
        removeUserBtn.setBaseColor(UIConstants.ERROR_LIGHT);
        removeUserBtn.setForeground(UIConstants.ERROR_DARK);
        removeUserBtn.addActionListener(e -> removeSelectedUser());
        
        buttonPanel.add(addUserBtn);
        buttonPanel.add(removeUserBtn);
        
        add(buttonPanel, BorderLayout.SOUTH);
    }
    
    public void loadUsers() {
        tableModel.setRowCount(0);
        allUsers = DataManager.getInstance().getUsers();
        
        for (User user : allUsers) {
            tableModel.addRow(new Object[]{
                user.getUserId(),
                user.getName(),
                user.getUsername(),
                user.getRole(),
                user.getEmail()
            });
        }
    }
    
    private void openAddUserDialog() {
        new AddUserDialog((JFrame) SwingUtilities.getWindowAncestor(this), this);
    }
    
    private void removeSelectedUser() {
        int selectedRow = userTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, 
                "Please select a user to remove.", "No User Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        User userToRemove = allUsers.get(selectedRow);
        
        if (userToRemove.getRole() == UserRole.ADMIN) {
            JOptionPane.showMessageDialog(this, 
                "Cannot remove an Admin user.", "Action Denied", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        int choice = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to remove " + userToRemove.getName() + "?\nThis action cannot be undone.",
            "Confirm Removal", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            
        if (choice == JOptionPane.YES_OPTION) {
            DataManager.getInstance().removeUser(userToRemove);
            loadUsers(); // Refresh the table
        }
    }
    
    private void setupTableStyle(JTable table) {
        table.setRowHeight(40);
        table.setGridColor(UIConstants.BORDER);
        table.setSelectionBackground(UIConstants.PRIMARY.darker());
        table.setSelectionForeground(Color.WHITE);
        table.setFont(UIConstants.BODY_FONT);
        
        JTableHeader header = table.getTableHeader();
        header.setFont(UIConstants.BUTTON_FONT);
        header.setBackground(UIConstants.BACKGROUND);
        header.setForeground(UIConstants.TEXT_DARK);
        header.setPreferredSize(new Dimension(0, 45));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIConstants.BORDER));
    }
}

/**
 * New Panel for Admins to edit attendance.
 * This is based on the Teacher's AttendancePanel but adapted for Admin.
 */
class AdminAttendancePanel extends JPanel {
    private JComboBox<Subject> subjectCombo;
    private JSpinner dateSpinner;
    private JTable attendanceTable;
    private DefaultTableModel tableModel;
    private List<Student> currentStudents;
    private Admin admin;

    public AdminAttendancePanel(Admin admin) {
        this.admin = admin;
        setLayout(new BorderLayout(15, 15));
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        initComponents();
    }

    private void initComponents() {
        JLabel titleLabel = new JLabel("Manage Student Attendance");
        titleLabel.setFont(UIConstants.TITLE_FONT);
        titleLabel.setForeground(UIConstants.TEXT_DARK);

        // Top Panel
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 10));
        topPanel.setBackground(Color.WHITE);

        topPanel.add(new JLabel("Date:"));
        SpinnerDateModel dateModel = new SpinnerDateModel(new Date(), null, null, Calendar.DAY_OF_MONTH);
        dateSpinner = new JSpinner(dateModel);
        JSpinner.DateEditor dateEditor = new JSpinner.DateEditor(dateSpinner, "dd MMMM yyyy");
        dateSpinner.setEditor(dateEditor);
        dateSpinner.setPreferredSize(new Dimension(160, 40));
        dateSpinner.setFont(UIConstants.BODY_FONT);
        dateSpinner.addChangeListener(e -> loadStudentsForDate());
        topPanel.add(dateSpinner);

        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(new JLabel("Subject:"));

        subjectCombo = new JComboBox<>();
        subjectCombo.setPreferredSize(new Dimension(300, 40));
        subjectCombo.setFont(UIConstants.BODY_FONT);
        for (Subject s : DataManager.getInstance().getSubjects()) {
            subjectCombo.addItem(s);
        }
        subjectCombo.addActionListener(e -> loadStudentsForDate());
        topPanel.add(subjectCombo);
        
        // Table
        String[] columns = {"Roll No", "Student Name", "Status", "Marked By"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2; // Only Status is editable
            }
        };

        attendanceTable = new JTable(tableModel);
        setupTableStyle(attendanceTable);

        JComboBox<AttendanceStatus> statusCombo = new JComboBox<>(AttendanceStatus.values());
        attendanceTable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(statusCombo));
        
        // Custom renderer for status column
        attendanceTable.getColumnModel().getColumn(2).setCellRenderer(new AttendanceStatusRenderer());
        
        loadStudentsForDate();

        // Bottom Panel
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.setBackground(Color.WHITE);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        NeumorphicButton saveBtn = new NeumorphicButton("✔ Save Changes");
        saveBtn.setPreferredSize(new Dimension(220, 45));
        saveBtn.setBaseColor(UIConstants.SUCCESS_LIGHT);
        saveBtn.setForeground(UIConstants.SUCCESS_DARK);
        saveBtn.addActionListener(e -> saveAttendance());
        bottomPanel.add(saveBtn);

        // Assembly
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.setBackground(Color.WHITE);
        northPanel.add(titleLabel, BorderLayout.NORTH);
        northPanel.add(topPanel, BorderLayout.CENTER);

        add(northPanel, BorderLayout.NORTH);
    add(new CardPanel(new JScrollPane(attendanceTable)), BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private void setupTableStyle(JTable table) {
        table.setRowHeight(40);
        table.setGridColor(UIConstants.BORDER);
        table.setSelectionBackground(UIConstants.PRIMARY.darker());
        table.setSelectionForeground(Color.WHITE);
        table.setFont(UIConstants.BODY_FONT);
        
        JTableHeader header = table.getTableHeader();
        header.setFont(UIConstants.BUTTON_FONT);
        header.setBackground(UIConstants.BACKGROUND);
        header.setForeground(UIConstants.TEXT_DARK);
        header.setPreferredSize(new Dimension(0, 45));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIConstants.BORDER));
    }

    private void loadStudentsForDate() {
        tableModel.setRowCount(0);
        currentStudents = new ArrayList<>();
        
        Subject subject = (Subject) subjectCombo.getSelectedItem();
        if (subject == null) return;
        
        Date selectedDate = (Date) dateSpinner.getValue();
        LocalDate date = selectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        
        // Load *all* attendance for this date
        List<AttendanceRecord> allDayRecords = DataManager.getInstance().getAttendanceForDate(date);
        
        // Filter for this subject
        Map<String, AttendanceRecord> subjectRecords = new HashMap<>();
        for (AttendanceRecord record : allDayRecords) {
            if (record.getSubjectId().equals(subject.getSubjectId())) {
                subjectRecords.put(record.getStudentId(), record);
            }
        }
        
        for (String studentId : subject.getEnrolledStudents()) {
            Student s = DataManager.getInstance().getStudent(studentId);
            if (s != null) {
                currentStudents.add(s);
                
                AttendanceRecord existingRecord = subjectRecords.get(studentId);
                AttendanceStatus status = AttendanceStatus.ABSENT; // Default
                String markedBy = "N/A";
                
                if (existingRecord != null) {
                    status = existingRecord.getStatus();
                    markedBy = existingRecord.getMarkedBy();
                }
                
                tableModel.addRow(new Object[]{
                    s.getRollNumber(), 
                    s.getName(), 
                    status,
                    markedBy
                });
            }
        }
    }

    private void saveAttendance() {
        if (currentStudents.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No students to mark attendance for!");
            return;
        }
        
        Subject subject = (Subject) subjectCombo.getSelectedItem();
        if (subject == null) return;

        Date selectedDate = (Date) dateSpinner.getValue();
        LocalDate date = selectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        
        List<AttendanceRecord> recordsToSave = new ArrayList<>();
        
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            Student student = currentStudents.get(i);
            AttendanceStatus status = (AttendanceStatus) tableModel.getValueAt(i, 2);
            
            AttendanceRecord record = new AttendanceRecord(
                student.getStudentId(), subject.getSubjectId(), 
                date, status, admin.getUserId()); // Marked by Admin
            recordsToSave.add(record);
        }
        
        // Call the fixed DataManager method
        DataManager.getInstance().markAttendanceForDate(date, subject.getSubjectId(), recordsToSave);
        
        JOptionPane.showMessageDialog(this, 
            "Attendance updated successfully by Admin for " + date + "!", 
            "Success", 
            JOptionPane.INFORMATION_MESSAGE);
            
        loadStudentsForDate(); // Refresh table to show "Marked By"
    }
}

class AdminReportPanel extends JPanel {
    public AdminReportPanel() {
        // Placeholder
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        JLabel title = new JLabel("System Reports (Coming Soon)");
        title.setFont(UIConstants.TITLE_FONT);
        add(title, BorderLayout.NORTH);
    }
}

// ==================== TEACHER DASHBOARD (Redesigned) ====================
class TeacherDashboard extends BaseDashboardFrame {
    public TeacherDashboard(Teacher teacher) {
        super(teacher);
        
        JPanel sidebar = createSidebar();
        initComponents("TEACHER DASHBOARD", sidebar);
        
        contentPanel.add(new AttendancePanel(teacher), "Mark Attendance");
        contentPanel.add(new ViewReportsPanel(), "View Reports");
        contentPanel.add(new LeaveRequestPanel(), "Leave Requests");
        
        // Set default view
        cardLayout.show(contentPanel, "Mark Attendance");
        ((JButton)sidebar.getComponent(1)).doClick(); // Highlight first button
        
        setVisible(true);
    }
    
    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(UIConstants.BACKGROUND);
        sidebar.setPreferredSize(new Dimension(230, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UIConstants.BORDER));
        
        sidebar.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // 
        sidebar.add(createMenuButton("Mark Attendance", "✓", "Mark Attendance"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("View Reports", "📊", "View Reports"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("Leave Requests", "📝", "Leave Requests"));
        
        sidebar.add(Box.createVerticalGlue());
        
        return sidebar;
    }
}

// --- Teacher Panels ---
class AttendancePanel extends JPanel {
    private JComboBox<Subject> subjectCombo;
    private JSpinner dateSpinner;
    private JTable attendanceTable;
    private DefaultTableModel tableModel;
    private List<Student> currentStudents;
    private Teacher teacher;
    private AttendanceServer attendanceServer;
    private JDialog bluetoothDialog;

    public AttendancePanel(Teacher teacher) {
        this.teacher = teacher;
        setLayout(new BorderLayout(15, 15));
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        initComponents();
    }

    private void initComponents() {
        JLabel titleLabel = new JLabel("Mark Attendance");
        titleLabel.setFont(UIConstants.TITLE_FONT);
        titleLabel.setForeground(UIConstants.TEXT_DARK);

        // Top Panel
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 10));
        topPanel.setBackground(Color.WHITE);

        topPanel.add(new JLabel("Date:"));
        SpinnerDateModel dateModel = new SpinnerDateModel(new Date(), null, null, Calendar.DAY_OF_MONTH);
        dateSpinner = new JSpinner(dateModel);
        JSpinner.DateEditor dateEditor = new JSpinner.DateEditor(dateSpinner, "dd MMMM yyyy");
        dateSpinner.setEditor(dateEditor);
        dateSpinner.setPreferredSize(new Dimension(160, 40));
        dateSpinner.setFont(UIConstants.BODY_FONT);
        dateSpinner.addChangeListener(e -> loadStudentsForDate());
        topPanel.add(dateSpinner);

        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(new JLabel("Subject:"));

        subjectCombo = new JComboBox<>();
        subjectCombo.setPreferredSize(new Dimension(300, 40));
        subjectCombo.setFont(UIConstants.BODY_FONT);
        // Only show subjects for this teacher's department
        for (Subject s : DataManager.getInstance().getSubjects()) {
            if (s.getDepartment().equals(teacher.getDepartment())) {
                subjectCombo.addItem(s);
            }
        }
        subjectCombo.addActionListener(e -> loadStudentsForDate());
        topPanel.add(subjectCombo);
        
        topPanel.add(Box.createHorizontalStrut(20));
        
    NeumorphicButton markAllPresent = new NeumorphicButton("✓ All Present");
    markAllPresent.setPreferredSize(new Dimension(130, 35));
    markAllPresent.setBaseColor(UIConstants.SUCCESS);
    markAllPresent.addActionListener(e -> markAll(AttendanceStatus.PRESENT));
    topPanel.add(markAllPresent);
        
    NeumorphicButton markAllAbsent = new NeumorphicButton("✗ All Absent");
    markAllAbsent.setPreferredSize(new Dimension(130, 35));
    markAllAbsent.setBaseColor(UIConstants.ERROR);
    markAllAbsent.addActionListener(e -> markAll(AttendanceStatus.ABSENT));
    topPanel.add(markAllAbsent);

        // Table
        String[] columns = {"Roll No", "Student Name", "Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2;
            }
        };

        attendanceTable = new JTable(tableModel);
        setupTableStyle(attendanceTable);

        JComboBox<AttendanceStatus> statusCombo = new JComboBox<>(AttendanceStatus.values());
        attendanceTable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(statusCombo));
        
        // Custom renderer for status column
        attendanceTable.getColumnModel().getColumn(2).setCellRenderer(new AttendanceStatusRenderer());
        
        loadStudentsForDate();

        // Bottom Panel
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.setBackground(Color.WHITE);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        NeumorphicButton startBluetoothBtn = new NeumorphicButton("📱 Start Bluetooth Portal");
        startBluetoothBtn.setPreferredSize(new Dimension(220, 45));
        startBluetoothBtn.setBaseColor(new Color(79, 70, 229));
        startBluetoothBtn.addActionListener(e -> startBluetoothAttendance());
        bottomPanel.add(startBluetoothBtn);

        bottomPanel.add(Box.createHorizontalStrut(12));

        // Refresh button: reloads serialized data and updates UI entries (neumorphic)
        NeumorphicButton refreshBtn = new NeumorphicButton("🔄 Refresh");
        refreshBtn.setPreferredSize(new Dimension(140, 40));
        refreshBtn.setBaseColor(UIConstants.PRIMARY);
        refreshBtn.addActionListener(e -> {
            // Reload persistent data
            DataManager.getInstance().loadAllData();

            // Repopulate the subject combo for this teacher's department
            subjectCombo.removeAllItems();
            for (Subject s : DataManager.getInstance().getSubjects()) {
                if (s.getDepartment().equals(teacher.getDepartment())) {
                    subjectCombo.addItem(s);
                }
            }

            // Refresh the students table for the currently selected date/subject
            loadStudentsForDate();

            JOptionPane.showMessageDialog(this, "System refreshed and entries updated.", "Refreshed", JOptionPane.INFORMATION_MESSAGE);
        });
        bottomPanel.add(refreshBtn);

        bottomPanel.add(Box.createHorizontalStrut(12));

        NeumorphicButton saveBtn = new NeumorphicButton("💾 Save Attendance");
        saveBtn.setPreferredSize(new Dimension(200, 45));
        saveBtn.setBaseColor(UIConstants.SUCCESS);
        saveBtn.addActionListener(e -> saveAttendance());
        bottomPanel.add(saveBtn);

        // Assembly
        JPanel northPanel = new JPanel(new BorderLayout());
        northPanel.setBackground(Color.WHITE);
        northPanel.add(titleLabel, BorderLayout.NORTH);
        northPanel.add(topPanel, BorderLayout.CENTER);

        add(northPanel, BorderLayout.NORTH);
    add(new CardPanel(new JScrollPane(attendanceTable)), BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }
    
    private void setupTableStyle(JTable table) {
        table.setRowHeight(40);
        table.setGridColor(UIConstants.BORDER);
        table.setSelectionBackground(UIConstants.PRIMARY.darker());
        table.setSelectionForeground(Color.WHITE);
        table.setFont(UIConstants.BODY_FONT);
        
        JTableHeader header = table.getTableHeader();
        header.setFont(UIConstants.BUTTON_FONT);
        header.setBackground(UIConstants.BACKGROUND);
        header.setForeground(UIConstants.TEXT_DARK);
        header.setPreferredSize(new Dimension(0, 45));
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIConstants.BORDER));
    }

    private void loadStudentsForDate() {
        tableModel.setRowCount(0);
        currentStudents = new ArrayList<>();
        
        Subject subject = (Subject) subjectCombo.getSelectedItem();
        if (subject == null) return;
        
        Date selectedDate = (Date) dateSpinner.getValue();
        LocalDate date = selectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        
        // Load *all* attendance for this date
        List<AttendanceRecord> allDayRecords = DataManager.getInstance().getAttendanceForDate(date);
        
        // Filter for this subject
        Map<String, AttendanceStatus> subjectRecords = new HashMap<>();
        for (AttendanceRecord record : allDayRecords) {
            if (record.getSubjectId().equals(subject.getSubjectId())) {
                subjectRecords.put(record.getStudentId(), record.getStatus());
            }
        }
        
        for (String studentId : subject.getEnrolledStudents()) {
            Student s = DataManager.getInstance().getStudent(studentId);
            if (s != null) {
                currentStudents.add(s);
                // Default to PRESENT for a new sheet
                AttendanceStatus status = subjectRecords.getOrDefault(studentId, AttendanceStatus.PRESENT);
                tableModel.addRow(new Object[]{
                    s.getRollNumber(), 
                    s.getName(), 
                    status
                });
            }
        }
    }
    
    private void markAll(AttendanceStatus status) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            tableModel.setValueAt(status, i, 2);
        }
    }

    private void startBluetoothAttendance() {
        Subject subject = (Subject) subjectCombo.getSelectedItem();
        if (subject == null) {
            JOptionPane.showMessageDialog(this, 
                "Please select a subject first.", 
                "Subject Required", 
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        Date selectedDate = (Date) dateSpinner.getValue();
        LocalDate date = selectedDate.toInstant()
            .atZone(ZoneId.systemDefault()).toLocalDate();

        // Create and start the hybrid Attendance server (Bluetooth preferred)
        attendanceServer = new AttendanceServer(teacher, subject, date);
        String modeMessage;
        try {
            modeMessage = attendanceServer.startServer(); // attempts Bluetooth, falls back to Wi-Fi
            // Start background accept loop
            new Thread(attendanceServer).start();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, 
                "Failed to start attendance portal: " + ex.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
            attendanceServer = null;
            return;
        }

        // Show the status dialog with the detected mode
        showAttendanceStatusDialog(modeMessage);
        JOptionPane.showMessageDialog(this, "Attendance portal started: " + modeMessage,
            "Portal Active", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showAttendanceStatusDialog(String modeMessage) {
        bluetoothDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), 
                                    "Attendance Portal", false);
        bluetoothDialog.setLayout(new BorderLayout(20, 20));
        bluetoothDialog.setSize(480, 260);
        bluetoothDialog.setLocationRelativeTo(this);

        // Create content panel
        JPanel contentPanel = new JPanel(new BorderLayout(15, 15));
        contentPanel.setBackground(Color.WHITE);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Add status icon
        JLabel iconLabel = new JLabel("📡");
        iconLabel.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 48));
        iconLabel.setHorizontalAlignment(SwingConstants.CENTER);
        contentPanel.add(iconLabel, BorderLayout.NORTH);

        // Add status text
        JLabel statusLabel = new JLabel("<html><center>" +
            modeMessage +
            "<br><br>Waiting for student devices...<br><br>" +
            "Students: Ensure Bluetooth or Wi-Fi (as instructed) is enabled and biometric verification is complete." +
            "</center></html>");
        statusLabel.setFont(UIConstants.BODY_FONT);
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        contentPanel.add(statusLabel, BorderLayout.CENTER);

        // Add stop button
        NeumorphicButton stopBtn = new NeumorphicButton("Stop Attendance Portal");
        stopBtn.setPreferredSize(new Dimension(200, 40));
        stopBtn.setBaseColor(UIConstants.ERROR_LIGHT);
        stopBtn.setForeground(UIConstants.ERROR_DARK);
        stopBtn.addActionListener(e -> stopAttendancePortal());
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.setBackground(Color.WHITE);
        buttonPanel.add(stopBtn);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        bluetoothDialog.add(contentPanel);
        bluetoothDialog.setVisible(true);
    }

    private void stopAttendancePortal() {
        if (attendanceServer != null) {
            attendanceServer.stop();
            attendanceServer = null;
        }
        if (bluetoothDialog != null) {
            bluetoothDialog.dispose();
            bluetoothDialog = null;
        }
        JOptionPane.showMessageDialog(this, 
            "Attendance Portal has been stopped.", 
            "Portal Closed", 
            JOptionPane.INFORMATION_MESSAGE);
    }

    private void saveAttendance() {
        if (currentStudents.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No students to mark attendance for!");
            return;
        }
        
        Subject subject = (Subject) subjectCombo.getSelectedItem();
        if (subject == null) return;
        
        Date selectedDate = (Date) dateSpinner.getValue();
        LocalDate date = selectedDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        
        List<AttendanceRecord> recordsToSave = new ArrayList<>();
        
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            Student student = currentStudents.get(i);
            AttendanceStatus status = (AttendanceStatus) tableModel.getValueAt(i, 2);
            
            AttendanceRecord record = new AttendanceRecord(
                student.getStudentId(), subject.getSubjectId(), 
                date, status, teacher.getUserId()); // Marked by Teacher
            recordsToSave.add(record);
        }
        
        // --- Use the CRITICAL BUG FIX ---
        // Pass the subjectId so we only update records for this subject
        DataManager.getInstance().markAttendanceForDate(date, subject.getSubjectId(), recordsToSave);
        
        JOptionPane.showMessageDialog(this, 
            "Attendance saved successfully for " + date + "!", 
            "Success", 
            JOptionPane.INFORMATION_MESSAGE);
    }
}

/**
 * Custom renderer to color-code the attendance status in tables.
 */
class AttendanceStatusRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, 
            boolean isSelected, boolean hasFocus, int row, int column) {
        
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        if (value instanceof AttendanceStatus) {
            AttendanceStatus status = (AttendanceStatus) value;
            setFont(UIConstants.BUTTON_FONT);
            setHorizontalAlignment(SwingConstants.CENTER);
            setText(status.toString());
            
            if (!isSelected) {
                switch (status) {
                    case PRESENT:
                        c.setBackground(UIConstants.SUCCESS.brighter().brighter());
                        c.setForeground(UIConstants.SUCCESS.darker());
                        break;
                    case ABSENT:
                        c.setBackground(UIConstants.ERROR.brighter().brighter());
                        c.setForeground(UIConstants.ERROR.darker());
                        break;
                    case LATE:
                        c.setBackground(UIConstants.WARNING.brighter().brighter());
                        c.setForeground(UIConstants.WARNING.darker());
                        break;
                }
            }
        }
        return c;
    }
}

class ViewReportsPanel extends JPanel {
    public ViewReportsPanel() {
        // Placeholder
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        JLabel title = new JLabel("Attendance Reports (Coming Soon)");
        title.setFont(UIConstants.TITLE_FONT);
        add(title, BorderLayout.NORTH);
    }
}

class LeaveRequestPanel extends JPanel {
    public LeaveRequestPanel() {
        // Placeholder
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(30, 30, 30, 30));
        JLabel title = new JLabel("Leave Requests (Coming Soon)");
        title.setFont(UIConstants.TITLE_FONT);
        add(title, BorderLayout.NORTH);
    }
}

// ==================== STUDENT DASHBOARD (Redesigned) ====================
class StudentDashboard extends BaseDashboardFrame {
    public StudentDashboard(Student student) {
        super(student);
        
        JPanel sidebar = createSidebar();
        initComponents("STUDENT DASHBOARD", sidebar);
        
        contentPanel.add(new MyAttendancePanel(student), "My Attendance");
        contentPanel.add(new ApplyLeavePanel(student), "Apply Leave");
        contentPanel.add(new MyNotificationsPanel(student), "Notifications");
        
        // Set default view
        cardLayout.show(contentPanel, "My Attendance");
        ((JButton)sidebar.getComponent(1)).doClick(); // Highlight first button
        
        setVisible(true);
    }
    
    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(UIConstants.BACKGROUND);
        sidebar.setPreferredSize(new Dimension(230, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UIConstants.BORDER));
        
        sidebar.add(Box.createRigidArea(new Dimension(0, 20)));
        
        // 
        sidebar.add(createMenuButton("My Attendance", "📊", "My Attendance"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("Apply Leave", "📝", "Apply Leave"));
        sidebar.add(Box.createRigidArea(new Dimension(0, 8)));
        
        // 
        sidebar.add(createMenuButton("Notifications", "🔔", "Notifications"));
        
        sidebar.add(Box.createVerticalGlue());
        
        return sidebar;
    }
}

// --- Student Panels ---
class MyAttendancePanel extends JPanel {
    private Student student;

    public MyAttendancePanel(Student student) {
        this.student = student;
        setLayout(new BorderLayout(20, 20));
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        
        JLabel title = new JLabel("My Attendance Overview");
        title.setFont(UIConstants.TITLE_FONT);
        title.setForeground(UIConstants.TEXT_DARK);

        JPanel cardsPanel = new JPanel(new GridLayout(0, 3, 25, 25));
        cardsPanel.setBackground(Color.WHITE);
        
        List<String> subjectIds = student.getEnrolledSubjects();
        if (subjectIds.isEmpty()) {
            cardsPanel.setLayout(new BorderLayout());
            JLabel noSubjects = new JLabel("You are not enrolled in any subjects yet.", SwingConstants.CENTER);
            noSubjects.setFont(UIConstants.HEADER_FONT);
            noSubjects.setForeground(UIConstants.TEXT_LIGHT);
            cardsPanel.add(noSubjects, BorderLayout.CENTER);
        } else {
            for (String subjectId : subjectIds) {
                Subject subject = DataManager.getInstance().getSubject(subjectId);
                if (subject != null) {
                    double percentage = DataManager.getInstance()
                        .calculateAttendancePercentage(student.getStudentId(), subjectId);
                    cardsPanel.add(createSubjectCard(subject.getSubjectName(), percentage));
                }
            }
        }
        
        add(title, BorderLayout.NORTH);
        add(new JScrollPane(cardsPanel), BorderLayout.CENTER);
    }

    private JPanel createSubjectCard(String subjectName, double percentage) {
        JPanel card = new JPanel(new BorderLayout(10, 15));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(UIConstants.BORDER, 1, true),
            BorderFactory.createEmptyBorder(20, 20, 20, 20)
        ));
        
        // Header with Icon and Title
        JPanel headerPanel = new JPanel(new BorderLayout(10, 0));
        headerPanel.setOpaque(false);
        
        // 
        JLabel iconLabel = new JLabel(new SubjectCardIcon());
        headerPanel.add(iconLabel, BorderLayout.WEST);
        
        JLabel nameLabel = new JLabel(subjectName);
        nameLabel.setFont(UIConstants.HEADER_FONT);
        nameLabel.setForeground(UIConstants.TEXT_DARK);
        headerPanel.add(nameLabel, BorderLayout.CENTER);
        
        // Progress Bar
        CircularProgressBar progressBar = new CircularProgressBar();
        progressBar.setValue(percentage);
        
        card.add(headerPanel, BorderLayout.NORTH);
        card.add(progressBar, BorderLayout.CENTER);
        
        return card;
    }
}

class ApplyLeavePanel extends JPanel {
    private Student student;
    private JTextArea reasonArea;
    private JComboBox<LeaveType> leaveTypeCombo;
    private JSpinner startDateSpinner, endDateSpinner;

    public ApplyLeavePanel(Student student) {
        this.student = student;
        setLayout(new BorderLayout(20, 20));
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        
        JLabel title = new JLabel("Apply for Leave");
        title.setFont(UIConstants.TITLE_FONT);
        
        // Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(Color.WHITE);
        formPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        // To constrain the form width
        JPanel formContainer = new JPanel(new FlowLayout(FlowLayout.CENTER));
        formContainer.setBackground(Color.WHITE);
        formContainer.add(formPanel);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(createLabel("Leave Type:"), gbc);
        
        gbc.gridx = 1;
        leaveTypeCombo = new JComboBox<>(LeaveType.values());
        leaveTypeCombo.setPreferredSize(new Dimension(350, 40));
        formPanel.add(leaveTypeCombo, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(createLabel("Start Date:"), gbc);
        
        gbc.gridx = 1;
        SpinnerDateModel startModel = new SpinnerDateModel(new Date(), null, null, Calendar.DAY_OF_MONTH);
        startDateSpinner = new JSpinner(startModel);
        startDateSpinner.setEditor(new JSpinner.DateEditor(startDateSpinner, "dd MMMM yyyy"));
        startDateSpinner.setPreferredSize(new Dimension(350, 40));
        formPanel.add(startDateSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        formPanel.add(createLabel("End Date:"), gbc);
        
        gbc.gridx = 1;
        SpinnerDateModel endModel = new SpinnerDateModel(new Date(), null, null, Calendar.DAY_OF_MONTH);
        endDateSpinner = new JSpinner(endModel);
        endDateSpinner.setEditor(new JSpinner.DateEditor(endDateSpinner, "dd MMMM yyyy"));
        endDateSpinner.setPreferredSize(new Dimension(350, 40));
        formPanel.add(endDateSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3; gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(createLabel("Reason:"), gbc);
        
        gbc.gridx = 1;
        reasonArea = new JTextArea(5, 20);
        reasonArea.setLineWrap(true);
        reasonArea.setWrapStyleWord(true);
        reasonArea.setFont(UIConstants.BODY_FONT);
        reasonArea.setBorder(BorderFactory.createLineBorder(UIConstants.BORDER));
        JScrollPane scrollPane = new JScrollPane(reasonArea);
        scrollPane.setPreferredSize(new Dimension(350, 120));
        formPanel.add(scrollPane, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(20, 0, 0, 0);
        NeumorphicButton submitBtn = new NeumorphicButton("Submit Leave Application");
        submitBtn.setPreferredSize(new Dimension(300, 45));
        submitBtn.setBaseColor(UIConstants.PRIMARY_LIGHT);
        submitBtn.setForeground(UIConstants.PRIMARY_DARK);
        submitBtn.addActionListener(e -> submitLeave());
        formPanel.add(submitBtn, gbc);
        
        add(title, BorderLayout.NORTH);
        add(formContainer, BorderLayout.CENTER);
    }
    
    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(UIConstants.BUTTON_FONT);
        return label;
    }

    private void submitLeave() {
        Date startDate = (Date) startDateSpinner.getValue();
        Date endDate = (Date) endDateSpinner.getValue();
        String reason = reasonArea.getText().trim();
        LeaveType type = (LeaveType) leaveTypeCombo.getSelectedItem();
        
        if (reason.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a reason for leave", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (startDate.after(endDate)) {
            JOptionPane.showMessageDialog(this, "Start date must be before or on end date", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        LocalDate start = startDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate end = endDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        
        LeaveApplication leave = new LeaveApplication(student.getStudentId(), start, end, reason, type);
        DataManager.getInstance().addLeave(leave);
        
        JOptionPane.showMessageDialog(this, "Leave application submitted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        reasonArea.setText("");
    }
}

class MyNotificationsPanel extends JPanel {
    public MyNotificationsPanel(Student student) {
        // Placeholder
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(25, 25, 25, 25));
        JLabel title = new JLabel("My Notifications (Coming Soon)");
        title.setFont(UIConstants.TITLE_FONT);
        add(title, BorderLayout.NORTH);
    }
}

/**
 * AttendanceServer supports hybrid operation: Bluetooth SPP server (preferred)
 * and a Wi-Fi TCP fallback on port 5050. It validates incoming packets and
 * marks attendance via DataManager.
 *
 * Protocol (line oriented UTF-8):
 *   Clients MUST send a single line terminated by '\n' with the following pipe-separated fields:
 *     studentId|simHash|ip|biometricFlag
 *   Example: S001|<sha256-hex>|192.168.1.45|1\n
 * Response is a single-line token: SUCCESS, DUPLICATE, or INVALID\n
 * TODO: Add HMAC + nonce/timestamp to protect against replay and spoofing. The current scheme
 * relies on SIM hash and same-/24-subnet checks and should be considered experimental.
 */
class AttendanceServer implements Runnable {
    private static final javax.bluetooth.UUID SERVICE_UUID = new javax.bluetooth.UUID("1101", true); // SPP
    private static final String SERVICE_NAME = "SmartAttendanceSystem";
    private static final int WIFI_PORT = 5050;

    private final Teacher teacher;
    private final Subject subject;
    private final LocalDate attendanceDate;
    private final Set<String> processedStudents = Collections.synchronizedSet(new HashSet<>());

    private volatile boolean isRunning = false;
    private enum Mode { NONE, BLUETOOTH, WIFI }
    private Mode mode = Mode.NONE;

    // Bluetooth server
    private StreamConnectionNotifier btServer = null;

    // Wi-Fi server
    private ServerSocket wifiServer = null;

    private String teacherIp;
    private DiscoveryBroadcaster broadcaster;
    private Thread broadcastThread;

    public AttendanceServer(Teacher teacher, Subject subject, LocalDate date) {
        this.teacher = teacher;
        this.subject = subject;
        this.attendanceDate = date;
        // Prefer an IPv4 address that's likely usable on the LAN (avoid loopback)
        this.teacherIp = getPreferredLocalIPv4();
    }

    /**
     * Attempts to start Bluetooth server; on failure, starts Wi-Fi server.
     * Returns a human-readable status message describing which mode is active.
     */
    public String startServer() throws Exception {
        // Try Bluetooth first
        try {
            startBluetoothServer();
            // Start the discovery broadcaster
            broadcaster = new DiscoveryBroadcaster(teacherIp, 5050, subject.getSubjectId(), attendanceDate.toString());
            broadcastThread = new Thread(broadcaster);
            broadcastThread.start();
            return "Bluetooth server active (SPP)";
        } catch (Throwable btEx) {
            // Bluetooth failed; log and fall back to Wi-Fi
            btEx.printStackTrace();
            try {
                startWifiServer();
                String localIp = getPreferredLocalIPv4();
                System.out.println("[AttendanceServer] Using Wi-Fi fallback on " + localIp + ":" + WIFI_PORT);
                // Start the discovery broadcaster
                broadcaster = new DiscoveryBroadcaster(teacherIp, 5050, subject.getSubjectId(), attendanceDate.toString());
                broadcastThread = new Thread(broadcaster);
                broadcastThread.start();
                return "Wi-Fi attendance portal running at " + localIp + ":" + WIFI_PORT;
            } catch (IOException ioEx) {
                ioEx.printStackTrace();
                throw new Exception("Unable to start Bluetooth or Wi-Fi attendance servers.");
            }
        }
    }

    private void startBluetoothServer() throws Exception {
        // Initialize local Bluetooth adapter and create SPP service
        LocalDevice localDevice = LocalDevice.getLocalDevice();
        if (!localDevice.setDiscoverable(DiscoveryAgent.GIAC)) {
            // Some platforms may return false; still attempt to open
        }

        String url = "btspp://localhost:" + SERVICE_UUID.toString() + ";name=" + SERVICE_NAME;
        btServer = (StreamConnectionNotifier) Connector.open(url);
        mode = Mode.BLUETOOTH;
        isRunning = true;
    }

    private void startWifiServer() throws IOException {
        wifiServer = new ServerSocket(WIFI_PORT);
        wifiServer.setReuseAddress(true);
        mode = Mode.WIFI;
        isRunning = true;
    }

    @Override
    public void run() {
        if (!isRunning) return;
        try {
            while (isRunning) {
                if (mode == Mode.BLUETOOTH && btServer != null) {
                    // Accept Bluetooth client
                    StreamConnection conn = btServer.acceptAndOpen();
                    new Thread(() -> handleBluetoothClient(conn)).start();
                } else if (mode == Mode.WIFI && wifiServer != null) {
                    // Accept TCP client
                    Socket client = wifiServer.accept();
                    new Thread(() -> handleWifiClient(client)).start();
                } else {
                    // No active server; sleep briefly
                    Thread.sleep(200);
                }
            }
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            stop();
        }
    }

private void handleWifiClient(Socket socket) {
    try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
         BufferedWriter writer = new BufferedWriter(
             new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {

        String packet = reader.readLine();
        System.out.println("[WiFi] Received: " + packet);

        String resp;
        try {
            resp = processPacket(packet);
        } catch (Exception ex) {
            ex.printStackTrace();
            resp = "ERROR";
        }

        System.out.println("[WiFi] Responding with: " + resp);
        writer.write(resp + "\n");
        writer.flush();

    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        try { socket.close(); } catch (IOException ignored) {}
    }
}

private void handleBluetoothClient(StreamConnection connection) {
    try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.openInputStream(), StandardCharsets.UTF_8));
         BufferedWriter writer = new BufferedWriter(
             new OutputStreamWriter(connection.openOutputStream(), StandardCharsets.UTF_8))) {

        String packet = reader.readLine();
        System.out.println("[BT] Received: " + packet);

        String resp;
        try {
            resp = processPacket(packet);
        } catch (Exception ex) {
            ex.printStackTrace();
            resp = "ERROR";
        }

        System.out.println("[BT] Responding with: " + resp);
        writer.write(resp + "\n");
        writer.flush();

    } catch (IOException e) {
        e.printStackTrace();
    } finally {
        try { connection.close(); } catch (IOException ignored) {}
    }
}


    /**
     * Validates packet and records attendance when valid.
     * Returns one of: SUCCESS, DUPLICATE, INVALID
     */
    private String processPacket(String packet) {
        try {
            if (packet == null || packet.trim().isEmpty()) return "INVALID";
            boolean ok = SecurityUtils.verifyAttendancePacket(packet.trim(), teacherIp);
            String studentId = packet.split("\\|")[0];

            if (!ok) return "INVALID";

            synchronized (processedStudents) {
                if (processedStudents.contains(studentId)) return "DUPLICATE";
                processedStudents.add(studentId);
            }

            // Save attendance incrementally (replace any existing record for same student+subject)
            AttendanceRecord record = new AttendanceRecord(studentId, subject.getSubjectId(), attendanceDate, AttendanceStatus.PRESENT, teacher.getUserId());
            DataManager.getInstance().addAttendanceRecord(attendanceDate, record);

            return "SUCCESS";
        } catch (Exception e) {
            e.printStackTrace();
            return "INVALID";
        }
    }

    /**
     * Returns a preferred IPv4 address for the local host by scanning network interfaces.
     * Attempts to pick a private LAN address (10.*, 192.168.*, 172.16-31.*) and falls back
     * to the first non-loopback IPv4 found or 127.0.0.1 as a last resort.
     */
    private static String getPreferredLocalIPv4() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> ifaces = java.net.NetworkInterface.getNetworkInterfaces();
            java.util.List<String> candidates = new ArrayList<>();
            while (ifaces.hasMoreElements()) {
                java.net.NetworkInterface ni = ifaces.nextElement();
                if (ni.isLoopback() || !ni.isUp() || ni.isVirtual()) continue;
                java.util.Enumeration<java.net.InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    java.net.InetAddress addr = addrs.nextElement();
                    if (addr instanceof java.net.Inet4Address && !addr.isLoopbackAddress() && !addr.isLinkLocalAddress()) {
                        candidates.add(addr.getHostAddress());
                    }
                }
            }

            // Prefer private ranges
            for (String ip : candidates) {
                if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) return ip;
            }
            if (!candidates.isEmpty()) return candidates.get(0);
        } catch (java.net.SocketException e) {
            e.printStackTrace();
        }
        return "127.0.0.1";
    }

    public void stop() {
        isRunning = false;
        // Stop the discovery broadcaster
        if (broadcaster != null) broadcaster.stop();
        if (broadcastThread != null && broadcastThread.isAlive()) {
            try {
                broadcastThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        try {
            if (btServer != null) {
                btServer.close();
                btServer = null;
            }
        } catch (IOException e) { e.printStackTrace(); }
        try {
            if (wifiServer != null) {
                wifiServer.close();
                wifiServer = null;
            }
        } catch (IOException e) { e.printStackTrace(); }
        mode = Mode.NONE;
    }
}
    
