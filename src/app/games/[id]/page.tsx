import React from "react";
import Link from "next/link";
import {
  Users,
  Layers,
  Dice6,
  Shield,
  Sword,
  Heart,
  Zap,
  ChevronLeft,
} from "lucide-react";

export default async function GamePage({
  params,
}: {
  params: Promise<{ id: number }>;
}) {
  const { id } = await params;
  return (
    <div className="min-h-screen bg-slate-950">
      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-6 py-12">
        <Link
          href={"/"}
          className="flex gap-2 items-center text-sm text-slate-400 hover:text-slate-200"
        >
          <ChevronLeft className="h-4 w-4" /> Back
        </Link>
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-white mb-4">
            Welcome to RPG Manager
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            What will we manage today?
          </p>
        </div>

        {/* Navigation Cards */}
        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* Tables Card */}
          <Link href={`/games/${id}/tables`}>
            <div className="group relative bg-slate-950 border-1 border-indigo-500/30 rounded-xl overflow-hidden shadow-2xl hover:shadow-3xl transition-all duration-300 hover:border-indigo-500/60 backdrop-blur-sm cursor-pointer">
              {/* Glow effect */}
              <div className="absolute inset-0 bg-gradient-to-br from-indigo-400/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

              <div className="relative p-8">
                {/* Icon */}
                <div className="flex items-center justify-center w-16 h-16 bg-indigo-500/20 rounded-full border border-indigo-500/30 mb-6 group-hover:bg-indigo-500/30 transition-colors">
                  <Layers className="h-8 w-8 text-indigo-400" />
                </div>

                {/* Title */}
                <h3 className="text-2xl font-bold text-white mb-4 group-hover:text-indigo-100 transition-colors">
                  Game Tables
                </h3>

                {/* Description */}
                <p className="text-slate-300 mb-6 leading-relaxed">
                  Organize your campaigns with custom tables. Create, edit, and
                  manage game data with flexible columns and random generators.
                </p>

                {/* Features */}
                <div className="space-y-3">
                  <div className="flex items-center gap-3 text-slate-400">
                    <Layers className="h-4 w-4 text-indigo-400" />
                    <span className="text-sm">Multiple game tables</span>
                  </div>
                  <div className="flex items-center gap-3 text-slate-400">
                    <Dice6 className="h-4 w-4 text-purple-400" />
                    <span className="text-sm">Random generators</span>
                  </div>
                  <div className="flex items-center gap-3 text-slate-400">
                    <Zap className="h-4 w-4 text-yellow-400" />
                    <span className="text-sm">Dynamic content management</span>
                  </div>
                </div>
              </div>
            </div>
          </Link>
          {/* Characters Card */}
          <Link href={`/games/${id}/characters`}>
            <div className="group relative bg-slate-950 border-1 border-emerald-500/30 rounded-xl overflow-hidden shadow-2xl hover:shadow-3xl transition-all duration-300 hover:border-emerald-500/60 backdrop-blur-sm cursor-pointer">
              {/* Glow effect */}
              <div className="absolute inset-0 bg-gradient-to-br from-emerald-400/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

              <div className="relative p-8">
                {/* Icon */}
                <div className="flex items-center justify-center w-16 h-16 bg-emerald-500/20 rounded-full border border-emerald-500/30 mb-6 group-hover:bg-emerald-500/30 transition-colors">
                  <Users className="h-8 w-8 text-emerald-400" />
                </div>

                {/* Title */}
                <h3 className="text-2xl font-bold text-white mb-4 group-hover:text-emerald-100 transition-colors">
                  Character Manager
                </h3>

                {/* Description */}
                <p className="text-slate-300 mb-6 leading-relaxed">
                  Create and manage your RPG characters. Track health, mana,
                  attack, defense, and other vital stats with an intuitive
                  interface.
                </p>

                {/* Features */}
                <div className="space-y-3">
                  <div className="flex items-center gap-3 text-slate-400">
                    <Heart className="h-4 w-4 text-red-400" />
                    <span className="text-sm">Health & Mana tracking</span>
                  </div>
                  <div className="flex items-center gap-3 text-slate-400">
                    <Sword className="h-4 w-4 text-orange-400" />
                    <span className="text-sm">Combat statistics</span>
                  </div>
                  <div className="flex items-center gap-3 text-slate-400">
                    <Shield className="h-4 w-4 text-blue-400" />
                    <span className="text-sm">Ally & enemy management</span>
                  </div>
                </div>
              </div>
            </div>
          </Link>
        </div>

        {/* Quick Stats or Additional Info */}
        <div className="mt-16 text-center">
          <div className="inline-flex items-center gap-6 px-8 py-4 bg-slate-800/50 rounded-md border border-slate-700 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-slate-400">
              <Users className="h-5 w-5 text-emerald-400" />
              <span className="text-sm">Character Management</span>
            </div>
            <div className="w-px h-6 bg-slate-600" />
            <div className="flex items-center gap-2 text-slate-400">
              <Layers className="h-5 w-5 text-indigo-400" />
              <span className="text-sm">Table Organization</span>
            </div>
            <div className="w-px h-6 bg-slate-600" />
            <div className="flex items-center gap-2 text-slate-400">
              <Dice6 className="h-5 w-5 text-purple-400" />
              <span className="text-sm">Campaign Tools</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
