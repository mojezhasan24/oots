import java.util.*;

public class ListStudents {
    public static void main(String[] args) {
        try {
            DataManager dm = DataManager.getInstance();

            // Access private field 'students' via reflection
            java.lang.reflect.Field f = DataManager.class.getDeclaredField("students");
            f.setAccessible(true);
            List<?> list = (List<?>) f.get(dm);

            for (Object obj : list) {
                Student s = (Student) obj;
                System.out.println("StudentId=" + s.getStudentId()
                        + ", Roll=" + s.getRollNumber()
                        + ", Phone=" + s.getPhone());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
