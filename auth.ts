import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';
import { User } from './app/lib/definitions';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const result = await sql<User>`select * from users where email = ${email}`;
    return result.rows[0];
  } catch (err) {
    console.error('Failed to fetch user:', err);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const user = await getUser(parsedCredentials.data.email);

        if (!user) return null;

        const match = await bcrypt.compare(
          parsedCredentials.data.password,
          user.password,
        );

        if (!match) return null;

        return user;
      },
    }),
  ],
});
