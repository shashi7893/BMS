package com.bms.login;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class LoginApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	public void testSetup(){
		String str = "test";
		assertEquals(str, "test");
	}

}
