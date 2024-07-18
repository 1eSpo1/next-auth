import GitHub from "next-auth/providers/github";
import Credentials from "next-auth/providers/credentials";
import {NextAuthConfig} from "next-auth";
import {LoginSchema} from "@/schemas";
import {getUserByEmail} from "@/data/user";
import bcrypt from "bcryptjs";

export default {
    providers: [
        Credentials({
            async authorize(credentials) {
                const validatedFields = LoginSchema.safeParse(credentials);
                if (validatedFields.success) {
                    const { password, email } = validatedFields.data

                    const user = await getUserByEmail(email);
                    if (!user || !user.password) return null

                    const passwordMath = await bcrypt.compare(
                        password,
                        user.password
                    )

                    if (passwordMath) {
                        return user
                    }
                }
                return null;
            }
        })
    ],
} satisfies NextAuthConfig