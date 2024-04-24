import { lucia } from "@/auth";
import type { APIContext } from "astro";
import { db, eq, User } from "astro:db";
import { Argon2id } from "oslo/password";
export const POST = async (context: APIContext): Promise<Response> => {
  //parse the form data
  const formData = await context.request.formData();
  const username = formData.get("username");
  const password = formData.get("password");

  //validate form data
  if (!username || !password) {
    return new Response("Username and password are required", { status: 400 });
  }

  if (typeof username !== "string") {
    return new Response("Username is invalid", {
      status: 400,
    });
  }
  if (typeof password !== "string") {
    return new Response("Password is invalid", {
      status: 400,
    });
  }
  //search the user
  const foundUser = (
    await db.select().from(User).where(eq(User.username, username))
  ).at(0);

  //if user doesn't found
  if (!foundUser) {
    return new Response("Incorrect username or password", {
      status: 400,
    });
  }

  //verify if user has password
  if (!foundUser.password) {
    return new Response("Password is invalid", {
      status: 400,
    });
  }

  const validPassword = await new Argon2id().verify(
    foundUser.password,
    password
  );

  //if password is not valid
  if (!validPassword) {
    return new Response("Incorrect username or password", {
      status: 400,
    });
  }

  //password is valid -> generate session
  const session = await lucia.createSession(foundUser.id, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  context.cookies.set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
  return context.redirect("/");
};
