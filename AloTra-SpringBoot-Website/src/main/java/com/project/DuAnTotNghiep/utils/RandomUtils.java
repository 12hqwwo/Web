package com.project.DuAnTotNghiep.utils;

import java.util.Random;

public class RandomUtils {

	public static String generateRandomOrderId(int length) {
		String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		StringBuilder randomString = new StringBuilder();

		Random random = new Random();
		for (int i = 0; i < length; i++) {
			int index = random.nextInt(characters.length());
			randomString.append(characters.charAt(index));
		}

		return randomString.toString();
	}

	public static String randomAlphanumeric(int length) {
		String characters = "0123456789";
		StringBuilder randomString = new StringBuilder();

		Random random = new Random();
		for (int i = 0; i < length; i++) {
			int index = random.nextInt(characters.length());
			randomString.append(characters.charAt(index));
		}

		return randomString.toString();
	}
}
