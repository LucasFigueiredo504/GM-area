"use client";
import { useForm } from "react-hook-form";
import { AlertCircle, Shield, Sword, User, Lock, Mail } from "lucide-react";
import { signIn } from "@/actions/users";
import { useRouter } from "next/navigation";
import { useState } from "react";

type FormData = {
  email: string;
  password: string;
};

export default function SignInPage() {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({
    defaultValues: {
      email: "",
      password: "",
    },
  });
  const router = useRouter();
  const [serverError, setServerError] = useState<string>("");

  const onSubmit = async (data: FormData) => {
    try {
      setServerError("");

      await signIn(data.email, data.password);
      router.push("/");
    } catch (error) {
      console.log(error);

      if (error instanceof Error) {
        setServerError(error.message);
      } else {
        setServerError("An unexpected error occurred. Please try again.");
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-slate-950 rounded-lg shadow-xl overflow-hidden">
        {/* Header with logo */}
        <div className="p-6 bg-slate-900 flex flex-col items-center">
          <div className="bg-indigo-600 p-3 rounded-full mb-3">
            <Sword className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">RPG manager</h1>
          <p className="text-slate-400 mt-1">
            Sign in to command your adventure
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
          {(errors.email || errors.password || serverError) && (
            <div className="bg-red-900/20 border border-red-800 text-red-300 p-3 rounded-md flex items-start">
              <AlertCircle className="h-5 w-5 mr-2 mt-0.5 flex-shrink-0" />
              <span>
                {serverError ||
                  errors.email?.message ||
                  errors.password?.message}
              </span>
            </div>
          )}

          <div className="space-y-2">
            <label
              htmlFor="email"
              className="block text-sm font-medium text-slate-300"
            >
              Email Address
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Mail className="h-5 w-5 text-slate-500" />
              </div>
              <input
                id="email"
                type="email"
                {...register("email", {
                  required: "Please enter your email address",
                  pattern: {
                    value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                    message: "Invalid email address",
                  },
                })}
                className="block w-full pl-10 pr-3 py-2 border border-slate-700 rounded-md bg-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:border-transparent"
                placeholder="you@example.com"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label
              htmlFor="password"
              className="block text-sm font-medium text-slate-300"
            >
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-5 w-5 text-slate-500" />
              </div>
              <input
                id="password"
                type="password"
                {...register("password", {
                  required: "Please enter your password",
                  minLength: {
                    value: 8,
                    message: "Password must be at least 8 characters",
                  },
                })}
                className="block w-full pl-10 pr-3 py-2 border border-slate-700 rounded-md bg-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-600 focus:border-transparent"
                placeholder="••••••••"
              />
            </div>
          </div>

          {/*  <div className="flex items-end justify-between">
            <a
              href="#"
              className="text-sm font-medium text-indigo-400 hover:text-indigo-300"
            >
              Forgot password?
            </a>
          </div> */}

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full flex justify-center py-3 px-4 mt-12 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-75 disabled:cursor-not-allowed"
          >
            {isSubmitting ? (
              <>
                <svg
                  className="animate-spin -ml-1 mr-2 h-4 w-4 text-white"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  ></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
                Signing in...
              </>
            ) : (
              "Sign in"
            )}
          </button>

          <div className="mt-6 text-center">
            <p className="text-sm text-slate-400">
              Don't have an account?{" "}
              <a
                href="/signup"
                className="font-medium text-indigo-400 hover:text-indigo-300"
              >
                Create account
              </a>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
