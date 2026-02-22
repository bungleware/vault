import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Users, Lock, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { validateShareToken } from "@/api/sharing";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "@/routes/__root";
import LinkNotAvailable from "@/components/LinkNotAvailable";

export const Route = createFileRoute("/invite/$token")({
  component: InvitePage,
});

interface InviteData {
  valid: boolean;
  password_required?: boolean;
  track?: any;
  project?: any;
  project_id?: number;
  allow_editing?: boolean;
  allow_downloads?: boolean;
  error?: string;
}

function InvitePage() {
  const { token } = Route.useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [inviteData, setInviteData] = useState<InviteData | null>(null);
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState(false);
  const [isAccepting, setIsAccepting] = useState(false);

  const loadInviteData = async (pwd?: string) => {
    setIsLoading(true);
    setError(null);
    setPasswordError(false);

    try {
      const data = await validateShareToken(token, pwd);

      if (!data.valid) {
        if (data.password_required) {
          setInviteData({ ...data, valid: false });
          setPasswordError(pwd !== undefined);
        } else {
          setError(data.error || "Invalid invitation link");
        }
      } else {
        setInviteData(data as InviteData);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load invitation");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadInviteData();
  }, [token]);

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadInviteData(password);
  };

  const handleAcceptInvite = async () => {
    if (!user) {
      navigate({
        to: "/login",
        search: { returnTo: `/invite/${token}` },
      });
      return;
    }

    setIsAccepting(true);
    try {
      toast.success(
        `${inviteData?.track ? "Track" : "Project"} added to your library!`,
      );
      navigate({ to: "/" });
    } catch (err: any) {
      toast.error(err.message || "Failed to accept invitation");
    } finally {
      setIsAccepting(false);
    }
  };

  if (isLoading) {
    return null;
  }

  if (error) {
    return <LinkNotAvailable />;
  }

  if (inviteData && !inviteData.valid && inviteData.password_required) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          <div className="bg-linear-to-b from-[#1D1D1D] to-[#151515] border border-[#292828] rounded-3xl p-8">
            <div className="flex justify-center mb-6">
              <div className="w-16 h-16 rounded-full bg-white/10 flex items-center justify-center">
                <Lock className="size-8 text-white" />
              </div>
            </div>
            <h1 className="text-2xl font-semibold text-white text-center mb-2">
              Password Required
            </h1>
            <p className="text-muted-foreground text-center mb-6">
              This invitation is password protected
            </p>
            <form onSubmit={handlePasswordSubmit}>
              <Input
                type="password"
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={passwordError ? "border-red-500" : ""}
                autoFocus
              />
              {passwordError && (
                <p className="text-red-500 text-sm mt-2">Incorrect password</p>
              )}
              <Button type="submit" className="w-full mt-4">
                Unlock
              </Button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  if (inviteData && inviteData.valid) {
    const resource = inviteData.track || inviteData.project;
    const resourceType = inviteData.track ? "Track" : "Project";

    return (
      <div className="min-h-screen bg-[#0A0A0A] flex items-center justify-center p-4">
        <div className="w-full max-w-2xl">
          <div className="bg-linear-to-b from-[#1D1D1D] to-[#151515] border border-[#292828] rounded-[34px] p-8 md:p-12">
            <div className="flex justify-center mb-8">
              <div className="w-20 h-20 rounded-full bg-white/10 flex items-center justify-center">
                <Users className="size-10 text-white" />
              </div>
            </div>

            <div className="text-center mb-8">
              <div className="text-sm text-muted-foreground mb-2">
                You've been invited to
              </div>
              <h1 className="text-4xl font-semibold text-white mb-2">
                {resource.name || resource.title}
              </h1>
              <p className="text-xl text-muted-foreground">{resourceType}</p>
            </div>

            {resource.description && (
              <div className="mb-8 p-4 rounded-2xl bg-white/5">
                <p className="text-muted-foreground text-center">
                  {resource.description}
                </p>
              </div>
            )}

            <div className="flex flex-col gap-3">
              {user ? (
                <>
                  <Button
                    size="lg"
                    onClick={handleAcceptInvite}
                    disabled={isAccepting}
                    className="w-full"
                  >
                    {isAccepting ? (
                      "Adding to library..."
                    ) : (
                      <>
                        <Check className="size-5 mr-2" />
                        Accept Invitation & Add to Library
                      </>
                    )}
                  </Button>
                  <p className="text-sm text-muted-foreground text-center">
                    Signed in as {user.username}
                  </p>
                </>
              ) : (
                <>
                  <Button
                    size="lg"
                    onClick={handleAcceptInvite}
                    className="w-full"
                  >
                    Sign In to Accept
                  </Button>
                  <p className="text-sm text-muted-foreground text-center">
                    You need to sign in to add this to your library
                  </p>
                </>
              )}
            </div>

            <div className="mt-8 text-center">
              <a
                href="/"
                className="text-sm text-muted-foreground hover:text-white transition-colors"
              >
                Powered by Vault
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return null;
}
