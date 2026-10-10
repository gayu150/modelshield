import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { DEMO_MODE } from "../config";
import { currentUser, login, logout, register } from "../services/api/auth";
import { ApiError, safeMessage } from "../services/api/client";
import type { User } from "../types/auth";
type Auth = {
  user?: User;
  loading: boolean;
  error: string;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (name: string, email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  retry: () => void;
};
const Context = createContext<Auth | undefined>(undefined);
const demoUser: User = {
  id: "DEMO-USER",
  name: "Demo reviewer",
  email: "demo@modelshield.local",
  role: "Demo session",
};
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | undefined>(
    DEMO_MODE ? demoUser : undefined,
  );
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (DEMO_MODE) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    currentUser(controller.signal)
      .then((x) => {
        if (!controller.signal.aborted) setUser(x);
      })
      .catch((e) => {
        if (!controller.signal.aborted) {
          setUser(undefined);
          if (!(e instanceof ApiError && e.status === 401))
            setError(safeMessage(e));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => {
    const expire = () => {
      setUser(undefined);
      setError("");
      document.querySelector('meta[name="csrf-token"]')?.remove();
    };
    window.addEventListener("session-expired", expire);
    return () => window.removeEventListener("session-expired", expire);
  }, []);
  async function signIn(email: string, password: string) {
    setError("");
    setUser(DEMO_MODE ? demoUser : await login(email, password));
  }
  async function signUp(name: string, email: string, password: string) {
    setError("");
    setUser(
      DEMO_MODE
        ? { id: "DEMO-USER", name, email, role: "Demo session" }
        : await register(name, email, password),
    );
  }
  async function signOut() {
    if (!DEMO_MODE) await logout();
    setUser(undefined);
  }
  return (
    <Context.Provider
      value={{
        user,
        loading,
        error,
        signIn,
        signUp,
        signOut,
        retry: () => setRevision((x) => x + 1),
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function useAuth() {
  const value = useContext(Context);
  if (!value) throw new Error("AuthProvider is required.");
  return value;
}
