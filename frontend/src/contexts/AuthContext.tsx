import { createContext, useContext, useState, useEffect } from "react";
import type { ReactNode } from "react";
import type {
  User,
  LoginRequest,
  RegisterRequest,
  AuthResponse,
} from "../types/api";
import * as authApi from "../api/auth";

interface AuthContextType {
	user: User | null;
	isAuthenticated: boolean;
	isLoading: boolean;
	login: (credentials: LoginRequest) => Promise<void>;
	register: (data: RegisterRequest) => Promise<void>;
	setAuthFromResponse: (response: AuthResponse) => void;
	logout: () => Promise<void>;
	refreshUser: () => Promise<void>;
	updateUsername: (username: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
	const [user, setUser] = useState<User | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	useEffect(() => {
		const initAuth = async () => {
			try {
				await authApi.refresh();
				const userData = await authApi.getMe();
				setUser(userData);
			} catch (error: any) {
				setUser(null);
			}
			setIsLoading(false);
		};

    initAuth();
  }, []);

	const login = async (credentials: LoginRequest) => {
		const response: AuthResponse = await authApi.login(credentials);
		setUser(response.user);
	};

	const register = async (data: RegisterRequest) => {
		const response: AuthResponse = await authApi.register(data);
		setUser(response.user);
	};

	const setAuthFromResponse = (response: AuthResponse) => {
		setUser(response.user);
	};

	const logout = async () => {
		try {
			await authApi.logout();
		} catch {
		}
		setUser(null);
	};

  const refreshUser = async () => {
		try {
			const userData = await authApi.getMe();
			setUser(userData);
		} catch (error) {
			await logout();
		}
	};

  const updateUsername = async (username: string) => {
    try {
      const updatedUser = await authApi.updateUsername(username);
      setUser(updatedUser);
    } catch (error) {
      throw error;
    }
  };

	const value: AuthContextType = {
		user,
		isAuthenticated: !!user,
		isLoading,
		login,
		register,
		setAuthFromResponse,
    logout,
    refreshUser,
    updateUsername,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
