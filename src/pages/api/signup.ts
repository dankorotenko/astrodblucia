import type { APIContext } from "astro";
import { generateId } from "lucia";
import { Argon2id } from "oslo/password";
import { User, db } from "astro:db";
import { lucia } from "@/auth";

export const POST = async (context: APIContext): Promise<Response> => {
  //parse the form data
  const formData = await context.request.formData();
  const username = formData.get("username");
  const password = formData.get("password");

  //validate form data
  if (!username || !password) {
    return new Response("Username and password are required", { status: 400 });
  }

  if (typeof username !== "string" || username.length < 4) {
    return new Response("Username must be at least 4 characters long", {
      status: 400,
    });
  }

  if (typeof password !== "string" || password.length < 4) {
    return new Response("Password must be at least 4 characters long", {
      status: 400,
    });
  }
  //inser user into db
  const userId = generateId(15);

  const hashedPassowrd = await new Argon2id().hash(password);

  await db.insert(User).values([
    {
      id: userId,
      username,
      password: hashedPassowrd,
    },
  ]);

  //generate session
  const session = await lucia.createSession(userId, {});

  const sessionCookie = lucia.createSessionCookie(session.id);

  context.cookies.set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
  return context.redirect("/");
};
