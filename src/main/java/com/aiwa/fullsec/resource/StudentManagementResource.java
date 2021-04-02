package com.aiwa.fullsec.resource;

import com.aiwa.fullsec.model.Student;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping(path = "/management/api/v1/students")
public class StudentManagementResource {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "jamila"),
            new Student(2, "ana"),
            new Student(3, "ada"));

    @GetMapping
    public List<Student> getStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "/{studentId}")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println(studentId);
    }

    @PutMapping
    public void updateStudent(@RequestBody Student student) {
        System.out.println(student);
    }
}
