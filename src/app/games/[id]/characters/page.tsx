"use client";
import React, { useState } from "react";
import {
  Plus,
  Edit3,
  Check,
  X,
  Sword,
  Shield,
  Heart,
  Users,
  Zap,
  ChevronLeft,
} from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";

interface Character {
  id: number;
  name: string;
  attack: number;
  hp: number;
  maxHp: number;
  mana: number;
  maxMana: number;
  defense: number;
  type: "ally" | "enemy";
}

interface CharacterCardProps {
  character: Character;
  onUpdateCharacter: (id: number, updatedCharacter: Partial<Character>) => void;
  onDeleteCharacter: (id: number) => void;
}

interface NewCharacterCardProps {
  onClick: () => void;
  type: "ally" | "enemy";
}

const CharacterCard: React.FC<CharacterCardProps> = ({
  character,
  onUpdateCharacter,
  onDeleteCharacter,
}) => {
  const [isEditing, setIsEditing] = useState<string | null>(null);
  const [editValues, setEditValues] = useState<Partial<Character>>({});

  const isAlly = character.type === "ally";
  const hpPercentage = (character.hp / character.maxHp) * 100;
  const manaPercentage = (character.mana / character.maxMana) * 100;

  const handleEdit = (field: string, value: string | number) => {
    setIsEditing(field);
    setEditValues({ [field]: value });
  };

  const handleSave = (field: string) => {
    if (editValues[field as keyof Character] !== undefined) {
      const updatedFields: Partial<Character> = {
        [field]: editValues[field as keyof Character],
      };

      // If updating maxHp and it's less than current hp, also update hp
      if (
        field === "maxHp" &&
        editValues.maxHp &&
        editValues.maxHp < character.hp
      ) {
        updatedFields.hp = editValues.maxHp;
      }

      // If updating maxMana and it's less than current mana, also update mana
      if (
        field === "maxMana" &&
        editValues.maxMana &&
        editValues.maxMana < character.mana
      ) {
        updatedFields.mana = editValues.maxMana;
      }

      onUpdateCharacter(character.id, updatedFields);
    }
    setIsEditing(null);
    setEditValues({});
  };

  const handleCancel = () => {
    setIsEditing(null);
    setEditValues({});
  };

  const handleKeyPress = (e: React.KeyboardEvent, field: string) => {
    if (e.key === "Enter") {
      handleSave(field);
    } else if (e.key === "Escape") {
      handleCancel();
    }
  };

  // New increment/decrement functions
  const handleIncrement = (field: keyof Character, amount: number = 1) => {
    const currentValue = character[field] as number;
    let newValue = currentValue + amount;

    // Special handling for HP to not exceed maxHp
    if (field === "hp") {
      newValue = Math.min(newValue, character.maxHp);
    }

    // Special handling for mana to not exceed maxMana
    if (field === "mana") {
      newValue = Math.min(newValue, character.maxMana);
    }

    // Prevent negative values
    newValue = Math.max(0, newValue);

    onUpdateCharacter(character.id, { [field]: newValue });
  };

  const handleDecrement = (field: keyof Character, amount: number = 1) => {
    const currentValue = character[field] as number;
    let newValue = currentValue - amount;

    // Prevent negative values
    newValue = Math.max(0, newValue);

    onUpdateCharacter(character.id, { [field]: newValue });
  };

  return (
    <div
      className={`relative bg-gradient-to-br ${
        isAlly
          ? "from-emerald-950/80 to-slate-950 border-emerald-500/30"
          : "from-red-950/80 to-slate-950 border-red-500/30"
      } rounded-xl overflow-hidden shadow-2xl hover:shadow-3xl transition-all duration-300 border-2 hover:border-opacity-60 backdrop-blur-sm`}
    >
      {/* Character Type Badge */}
      <div
        className={`absolute top-3 left-3 px-2 py-1 rounded-full text-xs font-bold ${
          isAlly
            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
            : "bg-red-500/20 text-red-300 border border-red-500/30"
        }`}
      >
        {isAlly ? "ALLY" : "ENEMY"}
      </div>

      {/* Delete Button */}
      <button
        onClick={() => onDeleteCharacter(character.id)}
        className="absolute top-3 right-3 text-slate-400 hover:text-red-400 transition-colors z-10 bg-slate-800/50 rounded-full p-1 hover:bg-red-500/20"
      >
        <X className="h-4 w-4" />
      </button>

      <div className="p-6 pt-12">
        {/* Character Name */}
        <div className="mb-6">
          {isEditing === "name" ? (
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={editValues.name || ""}
                onChange={(e) =>
                  setEditValues({ ...editValues, name: e.target.value })
                }
                onKeyDown={(e) => handleKeyPress(e, "name")}
                className="text-2xl font-bold text-white bg-slate-800/60 border border-slate-600 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500 backdrop-blur-sm"
                autoFocus
              />
              <button
                onClick={() => handleSave("name")}
                className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded-full p-1"
              >
                <Check className="h-4 w-4" />
              </button>
              <button
                onClick={handleCancel}
                className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded-full p-1"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 group">
              <h3 className="text-2xl font-bold text-white">
                {character.name}
              </h3>
              <button
                onClick={() => handleEdit("name", character.name)}
                className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-indigo-400 transition-all bg-slate-800/50 rounded-full p-1"
              >
                <Edit3 className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* HP Bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Heart className="h-4 w-4 text-red-400" />
              <span className="text-slate-300 font-medium">Health</span>
            </div>
            <div className="flex items-center gap-1">
              {isEditing === "hp" ? (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={editValues.hp || ""}
                    onChange={(e) =>
                      setEditValues({
                        ...editValues,
                        hp: parseInt(e.target.value) || 0,
                      })
                    }
                    onKeyDown={(e) => handleKeyPress(e, "hp")}
                    className="w-16 text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    autoFocus
                  />
                  <button
                    onClick={() => handleSave("hp")}
                    className="text-green-400 hover:text-green-300"
                  >
                    <Check className="h-3 w-3" />
                  </button>
                  <button
                    onClick={handleCancel}
                    className="text-red-400 hover:text-red-300"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleDecrement("hp")}
                    className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    −
                  </button>
                  <button
                    onClick={() => handleEdit("hp", character.hp)}
                    className="text-white font-bold hover:text-red-400 transition-colors px-1"
                  >
                    {character.hp}
                  </button>
                  <button
                    onClick={() => handleIncrement("hp")}
                    className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    +
                  </button>
                </div>
              )}
              <span className="text-slate-400">/</span>
              {isEditing === "maxHp" ? (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={editValues.maxHp || ""}
                    onChange={(e) =>
                      setEditValues({
                        ...editValues,
                        maxHp: parseInt(e.target.value) || 0,
                      })
                    }
                    onKeyDown={(e) => handleKeyPress(e, "maxHp")}
                    className="w-16 text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    autoFocus
                  />
                  <button
                    onClick={() => handleSave("maxHp")}
                    className="text-green-400 hover:text-green-300"
                  >
                    <Check className="h-3 w-3" />
                  </button>
                  <button
                    onClick={handleCancel}
                    className="text-red-400 hover:text-red-300"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleDecrement("maxHp")}
                    className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    −
                  </button>
                  <button
                    onClick={() => handleEdit("maxHp", character.maxHp)}
                    className="text-slate-400 hover:text-white transition-colors px-1"
                  >
                    {character.maxHp}
                  </button>
                  <button
                    onClick={() => handleIncrement("maxHp")}
                    className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    +
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="w-full bg-slate-800/50 rounded-full h-3 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                hpPercentage > 60
                  ? "bg-green-500"
                  : hpPercentage > 30
                    ? "bg-yellow-500"
                    : "bg-red-500"
              }`}
              style={{ width: `${Math.max(0, Math.min(100, hpPercentage))}%` }}
            />
          </div>
        </div>

        {/* Mana Bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-blue-400" />
              <span className="text-slate-300 font-medium">Mana</span>
            </div>
            <div className="flex items-center gap-1">
              {isEditing === "mana" ? (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={editValues.mana || ""}
                    onChange={(e) =>
                      setEditValues({
                        ...editValues,
                        mana: parseInt(e.target.value) || 0,
                      })
                    }
                    onKeyDown={(e) => handleKeyPress(e, "mana")}
                    className="w-16 text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    autoFocus
                  />
                  <button
                    onClick={() => handleSave("mana")}
                    className="text-green-400 hover:text-green-300"
                  >
                    <Check className="h-3 w-3" />
                  </button>
                  <button
                    onClick={handleCancel}
                    className="text-red-400 hover:text-red-300"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleDecrement("mana")}
                    className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    −
                  </button>
                  <button
                    onClick={() => handleEdit("mana", character.mana)}
                    className="text-white font-bold hover:text-blue-400 transition-colors px-1"
                  >
                    {character.mana}
                  </button>
                  <button
                    onClick={() => handleIncrement("mana")}
                    className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    +
                  </button>
                </div>
              )}
              <span className="text-slate-400">/</span>
              {isEditing === "maxMana" ? (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={editValues.maxMana || ""}
                    onChange={(e) =>
                      setEditValues({
                        ...editValues,
                        maxMana: parseInt(e.target.value) || 0,
                      })
                    }
                    onKeyDown={(e) => handleKeyPress(e, "maxMana")}
                    className="w-16 text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    autoFocus
                  />
                  <button
                    onClick={() => handleSave("maxMana")}
                    className="text-green-400 hover:text-green-300"
                  >
                    <Check className="h-3 w-3" />
                  </button>
                  <button
                    onClick={handleCancel}
                    className="text-red-400 hover:text-red-300"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleDecrement("maxMana")}
                    className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    −
                  </button>
                  <button
                    onClick={() => handleEdit("maxMana", character.maxMana)}
                    className="text-slate-400 hover:text-white transition-colors px-1"
                  >
                    {character.maxMana}
                  </button>
                  <button
                    onClick={() => handleIncrement("maxMana")}
                    className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded px-1 transition-colors text-sm font-bold"
                  >
                    +
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="w-full bg-slate-800/50 rounded-full h-3 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                manaPercentage > 60
                  ? "bg-indigo-600"
                  : manaPercentage > 30
                    ? "bg-cyan-500"
                    : "bg-purple-500"
              }`}
              style={{
                width: `${Math.max(0, Math.min(100, manaPercentage))}%`,
              }}
            />
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 gap-4">
          {/* Attack Stat */}
          <div
            className={`${
              isAlly ? "bg-emerald-900/30" : "bg-red-900/30"
            } rounded-lg p-4 border ${
              isAlly ? "border-emerald-500/20" : "border-red-500/20"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Sword className="h-4 w-4 text-orange-400" />
                <span className="text-slate-300 text-sm font-medium">
                  Attack
                </span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => handleDecrement("attack")}
                  className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded w-6 h-6 flex items-center justify-center transition-colors text-xs font-bold"
                >
                  −
                </button>
                <button
                  onClick={() => handleIncrement("attack")}
                  className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded w-6 h-6 flex items-center justify-center transition-colors text-xs font-bold"
                >
                  +
                </button>
              </div>
            </div>
            {isEditing === "attack" ? (
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={editValues.attack || ""}
                  onChange={(e) =>
                    setEditValues({
                      ...editValues,
                      attack: parseInt(e.target.value) || 0,
                    })
                  }
                  onKeyDown={(e) => handleKeyPress(e, "attack")}
                  className="w-full text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  autoFocus
                />
                <button
                  onClick={() => handleSave("attack")}
                  className="text-green-400 hover:text-green-300"
                >
                  <Check className="h-3 w-3" />
                </button>
                <button
                  onClick={handleCancel}
                  className="text-red-400 hover:text-red-300"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => handleEdit("attack", character.attack)}
                className="text-2xl font-bold text-white hover:text-orange-400 transition-colors w-full text-left"
              >
                {character.attack}
              </button>
            )}
          </div>

          {/* Defense Stat */}
          <div
            className={`${
              isAlly ? "bg-emerald-900/30" : "bg-red-900/30"
            } rounded-lg p-4 border ${
              isAlly ? "border-emerald-500/20" : "border-red-500/20"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-blue-400" />
                <span className="text-slate-300 text-sm font-medium">
                  Defense
                </span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => handleDecrement("defense")}
                  className="text-red-400 hover:text-red-300 bg-slate-800/50 rounded w-6 h-6 flex items-center justify-center transition-colors text-xs font-bold"
                >
                  −
                </button>
                <button
                  onClick={() => handleIncrement("defense")}
                  className="text-green-400 hover:text-green-300 bg-slate-800/50 rounded w-6 h-6 flex items-center justify-center transition-colors text-xs font-bold"
                >
                  +
                </button>
              </div>
            </div>
            {isEditing === "defense" ? (
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={editValues.defense || ""}
                  onChange={(e) =>
                    setEditValues({
                      ...editValues,
                      defense: parseInt(e.target.value) || 0,
                    })
                  }
                  onKeyDown={(e) => handleKeyPress(e, "defense")}
                  className="w-full text-white bg-slate-800/60 border border-slate-600 rounded px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  autoFocus
                />
                <button
                  onClick={() => handleSave("defense")}
                  className="text-green-400 hover:text-green-300"
                >
                  <Check className="h-3 w-3" />
                </button>
                <button
                  onClick={handleCancel}
                  className="text-red-400 hover:text-red-300"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => handleEdit("defense", character.defense)}
                className="text-2xl font-bold text-white hover:text-blue-400 transition-colors w-full text-left"
              >
                {character.defense}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
const NewCharacterCard: React.FC<NewCharacterCardProps> = ({
  onClick,
  type,
}) => {
  const isAlly = type === "ally";

  return (
    <div
      onClick={onClick}
      className={`bg-gradient-to-br ${
        isAlly
          ? "from-emerald-950/30 to-slate-950/50 border-emerald-500/20 hover:border-emerald-400/40"
          : "from-red-950/30 to-slate-950/50 border-red-500/20 hover:border-red-400/40"
      } rounded-xl overflow-hidden shadow-lg border-2 border-dashed flex flex-col items-center justify-center p-8 cursor-pointer hover:bg-slate-800/30 transition-all duration-300 min-h-[280px] backdrop-blur-sm`}
    >
      <div
        className={`${
          isAlly ? "bg-emerald-500/20" : "bg-red-500/20"
        } p-4 rounded-full mb-4`}
      >
        <Plus
          className={`h-8 w-8 ${isAlly ? "text-emerald-400" : "text-red-400"}`}
        />
      </div>
      <h3 className="text-xl font-bold text-white mb-2">
        Add {isAlly ? "Ally" : "Enemy"}
      </h3>
      <p className="text-sm text-slate-400 text-center">
        Create a new {isAlly ? "ally" : "enemy"} character
      </p>
    </div>
  );
};

export default function CharactersPage() {
  const [characters, setCharacters] = useState<Character[]>([]);
  const [nextId, setNextId] = useState(1);

  const allies = characters.filter((char) => char.type === "ally");
  const enemies = characters.filter((char) => char.type === "enemy");

  const params = useParams();
  const id = params.id;

  const handleAddCharacter = (type: "ally" | "enemy") => {
    const newCharacter: Character = {
      id: nextId,
      name: `${type === "ally" ? "Ally" : "Enemy"} ${nextId}`,
      attack: Math.floor(Math.random() * 10) + 8,
      hp: Math.floor(Math.random() * 50) + 80,
      maxHp: Math.floor(Math.random() * 50) + 80,
      mana: Math.floor(Math.random() * 30) + 50,
      maxMana: Math.floor(Math.random() * 30) + 50,
      defense: Math.floor(Math.random() * 8) + 5,
      type,
    };
    // Ensure hp doesn't exceed maxHp
    newCharacter.hp = Math.min(newCharacter.hp, newCharacter.maxHp);

    setCharacters([...characters, newCharacter]);
    setNextId(nextId + 1);
  };

  const handleUpdateCharacter = (
    id: number,
    updatedFields: Partial<Character>,
  ) => {
    setCharacters(
      characters.map((char) =>
        char.id === id ? { ...char, ...updatedFields } : char,
      ),
    );
  };

  const handleDeleteCharacter = (id: number) => {
    setCharacters(characters.filter((char) => char.id !== id));
  };

  return (
    <div className="min-h-screen bg-slate-950">
      <div className="container mx-auto p-6">
        <header className="mb-8 text-center">
          <Link
            href={`/games/${id}`}
            className="flex gap-2 items-center text-sm text-slate-400 hover:text-slate-200"
          >
            <ChevronLeft className="h-4 w-4" /> Back
          </Link>
          <h1 className="text-4xl font-bold text-white mb-2">Battle Arena</h1>
          <p className="text-slate-400">
            Manage your allies and enemies for epic encounters
          </p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Allies Column */}
          <div>
            <div className="flex items-center gap-3 mb-6">
              <div className="bg-emerald-500/20 p-2 rounded-lg border border-emerald-500/30">
                <Users className="h-6 w-6 text-emerald-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">Allies</h2>
                <p className="text-sm text-emerald-400">
                  {allies.length} characters
                </p>
              </div>
            </div>

            <div className="space-y-4">
              {allies.map((character) => (
                <CharacterCard
                  key={character.id}
                  character={character}
                  onUpdateCharacter={handleUpdateCharacter}
                  onDeleteCharacter={handleDeleteCharacter}
                />
              ))}

              <NewCharacterCard
                onClick={() => handleAddCharacter("ally")}
                type="ally"
              />
            </div>
          </div>

          {/* Enemies Column */}
          <div>
            <div className="flex items-center gap-3 mb-6">
              <div className="bg-red-500/20 p-2 rounded-lg border border-red-500/30">
                <Zap className="h-6 w-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white">Enemies</h2>
                <p className="text-sm text-red-400">
                  {enemies.length} characters
                </p>
              </div>
            </div>

            <div className="space-y-4">
              {enemies.map((character) => (
                <CharacterCard
                  key={character.id}
                  character={character}
                  onUpdateCharacter={handleUpdateCharacter}
                  onDeleteCharacter={handleDeleteCharacter}
                />
              ))}

              <NewCharacterCard
                onClick={() => handleAddCharacter("enemy")}
                type="enemy"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
