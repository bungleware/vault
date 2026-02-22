import { useState } from "react";
import { Outlet, createFileRoute, useNavigate } from "@tanstack/react-router";
import { ChevronLeftIcon, MoreHorizontal, LogOut, Trash2 } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/contexts/AuthContext";
import { deleteAccount } from "@/api/auth";
import { toast } from "@/routes/__root";
import DeleteUserModal from "@/components/modals/DeleteUserModal";
import type { UserResponse } from "@/api/admin";

export const Route = createFileRoute("/profile")({
  component: ProfileLayout,
});

function ProfileLayout() {
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const deleteAccountMutation = useMutation({
    mutationFn: (password: string) => deleteAccount(password),
    onSuccess: () => {
      toast.success("Account deleted successfully");
      logout();
      navigate({ to: "/login" });
    },
    onError: (error: any) => {
      setDeleteError(error.message || "Failed to delete account");
    },
  });

  const handleLogout = () => {
    logout();
    navigate({ to: "/login" });
  };

  const handleDeleteConfirm = async (password?: string) => {
    if (!password) return;
    setDeleteError(null);
    await deleteAccountMutation.mutateAsync(password);
  };

  const deleteModalUser: UserResponse | null = user
    ? {
        id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin,
        is_owner: user.is_owner,
        created_at: user.created_at,
      }
    : null;

  return (
    <>
      <header className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between text-white md:p-10 p-6">
        <Button
          variant="default"
          size="icon-lg"
          onClick={() => navigate({ to: "/" })}
        >
          <ChevronLeftIcon className="size-4.5" />
        </Button>
        <div className="flex items-center gap-2.5">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="default" size="icon-lg">
                <MoreHorizontal strokeWidth={3} className="size-4.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              sideOffset={8}
              className="w-42 bg-[#1a1a1a] border border-[#353333] rounded-xl"
            >
              <DropdownMenuItem
                onSelect={handleLogout}
                className="text-base py-2"
              >
                <LogOut className="ml-1 mr-1.5 size-5" />
                Sign out
              </DropdownMenuItem>
              {!user?.is_admin && (
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={() => setIsDeleteModalOpen(true)}
                  className="text-base py-2"
                >
                  <Trash2 className="ml-1 mr-1.5 size-5" />
                  Delete account
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>
      <Outlet />

      <DeleteUserModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setDeleteError(null);
        }}
        onConfirm={handleDeleteConfirm}
        user={deleteModalUser}
        isDeleting={deleteAccountMutation.isPending}
        requirePassword
        title="Delete Account"
        warningText="This will permanently delete your account and all your projects, tracks, and data. This action cannot be undone."
        confirmText="Delete My Account"
        error={deleteError}
      />
    </>
  );
}
