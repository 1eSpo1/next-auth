'use server';

import * as z from "zod";
import { RegisterSchema} from "@/schemas";
import bcrypt from  'bcryptjs';
import { db } from "@/lib/db";
import {getUserByEmail, getUserById} from "@/data/user";

export const register = async (values: z.infer<typeof RegisterSchema>) => {
    const validatedFields = RegisterSchema.safeParse(values);

    if (!validatedFields.success) {
        return { error: "Invalid email or password!" };
    }

    const { email, password, name } = validatedFields.data;
    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await getUserByEmail(email);

    if (existingUser) {
        return { error: "User already exists!" };
    }

    await db.user.create({
        data: {
            email,
            password: hashedPassword,
            name
        }
    })

    // TODO: send verification token email

    return { success: "User created" };
}