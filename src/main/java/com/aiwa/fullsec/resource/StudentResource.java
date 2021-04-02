package com.aiwa.fullsec.resource;

import com.aiwa.fullsec.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping(path = "/api/v1/students")
public class StudentResource {

	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "jamila"),
			new Student(2, "ana"),
			new Student(3, "ada"));
	
	@GetMapping(path = "/{id}")
	public Student getStudent(@PathVariable Integer id) {
		return STUDENTS
				.stream()
				.filter(student -> student.getId().equals(id))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("Student with id "+id+" not found"));
	}

}
