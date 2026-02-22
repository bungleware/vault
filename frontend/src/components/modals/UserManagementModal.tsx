"use client";

import { useState, useEffect, useRef } from "react";
import { AnimatePresence, motion } from "motion/react";
import { createPortal } from "react-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import * as adminApi from "@/api/admin";
import { useAuth } from "@/contexts/AuthContext";
import {
  MoreVertical,
  Copy,
  Check,
  X,
  Plus,
  Trash2,
  RotateCcw,
  Shield,
  ShieldAlert,
  Pencil,
  Search,
  ChevronLeft,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import DeleteUserModal from "./DeleteUserModal";

export interface UserManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function UserManagementModal({
  isOpen,
  onClose,
}: UserManagementModalProps) {
  const queryClient = useQueryClient();
  const { user: currentUser, refreshUser } = useAuth();
  const [generatedInvite, setGeneratedInvite] = useState<{
    id: number;
    token: string;
    email: string;
    link: string;
  } | null>(null);
  const [generatedResetLink, setGeneratedResetLink] = useState<{
    id: number;
    token: string;
    email: string;
    link: string;
  } | null>(null);
  const [copiedTokenId, setCopiedTokenId] = useState<number | null>(null);
  const [copiedTitleTokenId, setCopiedTitleTokenId] = useState<number | null>(
    null,
  );
  const [invitePulse, setInvitePulse] = useState(0);
  const [resetPulse, setResetPulse] = useState(0);
  const copyResetTimeoutRef = useRef<number | null>(null);
  const [renamingUserId, setRenamingUserId] = useState<number | null>(null);
  const [newUsername, setNewUsername] = useState("");
  const [deleteConfirmingUser, setDeleteConfirmingUser] =
    useState<adminApi.UserResponse | null>(null);
  const [userSearchQuery, setUserSearchQuery] = useState("");

  useEffect(() => {
    if (!isOpen) {
      setGeneratedInvite(null);
      setGeneratedResetLink(null);
      setCopiedTokenId(null);
      setCopiedTitleTokenId(null);
      setDeleteConfirmingUser(null);
      setUserSearchQuery("");
    }
  }, [isOpen]);

  useEffect(() => {
    return () => {
      if (copyResetTimeoutRef.current) {
        window.clearTimeout(copyResetTimeoutRef.current);
      }
    };
  }, []);

  const {
    data: users = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ["admin", "users"],
    queryFn: adminApi.listUsers,
  });

  const createInviteMutation = useMutation({
    mutationFn: () => adminApi.createInvite(),
    onSuccess: (response) => {
      const origin =
        typeof window !== "undefined" ? window.location.origin : "";
      const inviteLink = `${origin}/accept-invite?token=${response.token}`;
      navigator.clipboard.writeText(inviteLink);
      setCopiedTitleTokenId(response.id);
      setGeneratedInvite({
        ...response,
        link: inviteLink,
      });
    },
    onError: (error: any) => {
      toast.error(error.message || "Failed to create invite");
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: (userId: number) => adminApi.deleteUser(userId),
    onSuccess: () => {
      queryClient.refetchQueries({ queryKey: ["admin", "users"] });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: ({ userId, isAdmin }: { userId: number; isAdmin: boolean }) =>
      adminApi.updateUserRole(userId, isAdmin),
    onSuccess: () => {
      queryClient.refetchQueries({ queryKey: ["admin", "users"] });
    },
  });

  const renameUserMutation = useMutation({
    mutationFn: ({ userId, username }: { userId: number; username: string }) =>
      adminApi.renameUser(userId, username),
    onSuccess: (_, { userId, username }) => {
      queryClient.setQueryData(
        ["admin", "users"],
        (old: adminApi.UserResponse[] | undefined) =>
          old?.map((u) => (u.id === userId ? { ...u, username } : u)),
      );
      setRenamingUserId(null);
      setNewUsername("");
      queryClient.refetchQueries({ queryKey: ["admin", "users"] });
      if (currentUser?.id === userId) {
        refreshUser();
      }
    },
  });

  const createResetLinkMutation = useMutation({
    mutationFn: (userId: number) => adminApi.createResetLink(userId),
    onSuccess: (response, userId) => {
      const origin =
        typeof window !== "undefined" ? window.location.origin : "";
      const resetLink = `${origin}/reset-password?token=${response.token}`;

      if (currentUser?.id === userId) {
        window.location.href = resetLink;
        return;
      }

      navigator.clipboard.writeText(resetLink);
      setCopiedTitleTokenId(response.id);
      setGeneratedResetLink({
        ...response,
        link: resetLink,
      });
      queryClient.refetchQueries({ queryKey: ["admin", "users"] });
    },
    onError: (error: any) => {
      toast.error(error.message || "Failed to create reset link");
    },
  });

  const handleCopyToken = (token: string, tokenId: number) => {
    if (copiedTokenId === tokenId) {
      setCopiedTokenId(null);
      setCopiedTitleTokenId(null);
    } else {
      navigator.clipboard.writeText(token);
      setCopiedTokenId(tokenId);
      setCopiedTitleTokenId(tokenId);
    }

    if (generatedInvite?.id === tokenId) {
      setInvitePulse((prev) => prev + 1);
    }
    if (generatedResetLink?.id === tokenId) {
      setResetPulse((prev) => prev + 1);
    }
  };

  const handleCreateInvite = async () => {
    await createInviteMutation.mutateAsync();
  };

  const handleDeleteUser = (user: adminApi.UserResponse) => {
    setDeleteConfirmingUser(user);
  };

  const handleConfirmDelete = async () => {
    if (deleteConfirmingUser !== null) {
      await deleteUserMutation.mutateAsync(deleteConfirmingUser.id);
      setDeleteConfirmingUser(null);
    }
  };

  const handleToggleAdmin = async (userId: number, currentIsAdmin: boolean) => {
    await updateRoleMutation.mutateAsync({
      userId,
      isAdmin: !currentIsAdmin,
    });
  };

  const handleRenameUser = async (userId: number) => {
    if (!newUsername.trim()) return;
    await renameUserMutation.mutateAsync({
      userId,
      username: newUsername,
    });
  };

  const handleCreateResetLink = async (userId: number) => {
    await createResetLinkMutation.mutateAsync(userId);
  };

  return createPortal(
    <>
      <style>{`
        @supports (animation-timeline: scroll()) {
          @property --ft {
            syntax: '<length>';
            inherits: false;
            initial-value: 0px;
          }
          @property --fb {
            syntax: '<length>';
            inherits: false;
            initial-value: 40px;
          }
          .scroll-fade-y {
            scroll-timeline-name: --scroller;
            mask-image: linear-gradient(
              to bottom,
              transparent 0,
              #000 var(--ft),
              #000 calc(100% - var(--fb)),
              transparent 100%
            );
            mask-size: 100% 100%;
            mask-repeat: no-repeat;
            animation: t 1s linear both, b 1s linear both;
            animation-timeline: scroll(self), scroll(self);
            animation-range: 0% 12%, 88% 100%;
          }
          .scroll-fade-y-parent {
            timeline-scope: --scroller;
          }
          .scroll-fade-bottom-gradient {
            animation: bg 1s linear both;
            animation-timeline: --scroller;
            animation-range: 88% 100%;
          }
          @keyframes t {
            from { --ft: 0px; }
            to { --ft: 40px; }
          }
          @keyframes b {
            from { --fb: 40px; }
            to { --fb: 0px; }
          }
          @keyframes bg {
            from { opacity: 1; }
            to { opacity: 0; }
          }
        }
      `}</style>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            key="user-management-modal"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-1000 flex items-center justify-center p-4"
          >
            {/* Backdrop */}
            <button
              type="button"
              className="absolute inset-0 bg-black/80"
              onClick={onClose}
              aria-label="Close user management modal"
            />

            {/* Modal Container */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.15 }}
              className="relative z-10 w-full max-w-2xl border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden"
              style={{
                background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="scroll-fade-y-parent flex flex-col h-[620px] relative">
                {/* Header */}
                <div className="flex items-center gap-4 p-6 pb-4">
                  <Button size="icon-lg" onClick={onClose} className="shrink-0">
                    <ChevronLeft className="size-5" />
                  </Button>
                  <div className="flex-1 min-w-0">
                    <h2
                      className="text-xl font-light text-white"
                      style={{ fontFamily: '"IBM Plex Mono", monospace' }}
                    >
                      Instance Users
                    </h2>
                    <p className="text-sm text-muted-foreground mt-0.5">
                      {users.length} {users.length === 1 ? "user" : "users"}
                    </p>
                  </div>
                </div>

                {/* Content */}
                <div className="scroll-fade-y flex flex-col gap-2 px-6 pt-2 pb-25 overflow-y-auto flex-1 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-white/10 hover:scrollbar-thumb-white/20">
                  {/* Error State */}
                  {error && (
                    <div className="mb-4 rounded-2xl border border-red-500/20 bg-gradient-to-br from-red-500/10 to-red-500/5 p-5">
                      <div className="flex items-center gap-3">
                        <div className="flex items-center justify-center size-9 rounded-xl bg-red-500/20">
                          <X className="size-4 text-red-400" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-white">
                            Failed to load users
                          </p>
                          <p className="text-xs text-red-400/70 mt-0.5">
                            Please try again or contact support
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Loading State */}
                  {isLoading && (
                    <div className="flex flex-col items-center justify-center py-16">
                      <div className="relative">
                        <div className="h-10 w-10 animate-spin rounded-full border-3 border-[#2a2a2a] border-t-[#0099bb]" />
                      </div>
                      <p className="text-sm text-[#6a6a6a] mt-4">
                        Loading users...
                      </p>
                    </div>
                  )}

                  {/* Users List */}
                  {!isLoading && (
                    <>
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
                        <Input
                          type="text"
                          placeholder="Search users..."
                          value={userSearchQuery}
                          onChange={(e) => setUserSearchQuery(e.target.value)}
                          className="pl-9 pr-8 text-white rounded-xl text-sm bg-white/5 border-white/10"
                        />
                        {userSearchQuery && (
                          <button
                            type="button"
                            onClick={() => setUserSearchQuery("")}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-white transition-colors"
                          >
                            <X className="size-3.5" />
                          </button>
                        )}
                      </div>

                      <div className="rounded-xl border border-white/10 divide-y divide-white/5 mt-3">
                        {(() => {
                          const filteredUsers = users
                            .sort((a, b) => {
                              if (!a.created_at || !b.created_at) return 0;
                              return (
                                new Date(a.created_at).getTime() -
                                new Date(b.created_at).getTime()
                              );
                            })
                            .filter((u) => {
                              if (!userSearchQuery) return true;
                              const q = userSearchQuery.toLowerCase();
                              return (
                                u.username.toLowerCase().includes(q) ||
                                u.email.toLowerCase().includes(q)
                              );
                            });

                          if (filteredUsers.length === 0) {
                            return (
                              <div className="px-4 py-6 text-center text-sm text-muted-foreground">
                                {userSearchQuery
                                  ? "No users found"
                                  : "No users yet — invite someone to get started"}
                              </div>
                            );
                          }

                          return filteredUsers.map((user) => (
                            <UserCard
                              key={user.id}
                              user={user}
                              currentUser={currentUser}
                              onToggleAdmin={() =>
                                handleToggleAdmin(user.id, user.is_admin)
                              }
                              onDelete={() => handleDeleteUser(user)}
                              onCreateResetLink={() =>
                                handleCreateResetLink(user.id)
                              }
                              onRenameClick={() => {
                                setRenamingUserId(user.id);
                                setNewUsername(user.username);
                              }}
                              renamingUserId={renamingUserId}
                              newUsername={newUsername}
                              onRenameChange={setNewUsername}
                              onRenameSave={() => handleRenameUser(user.id)}
                              onRenameCancel={() => setRenamingUserId(null)}
                              isDeleteMutating={deleteUserMutation.isPending}
                              isUpdateRoleMutating={
                                updateRoleMutation.isPending
                              }
                              isCreateResetMutating={
                                createResetLinkMutation.isPending
                              }
                            />
                          ));
                        })()}
                      </div>
                    </>
                  )}
                </div>

                {/* Bottom gradient overlay */}
                <div
                  className="scroll-fade-bottom-gradient absolute bottom-0 left-0 right-0 h-[140px] z-10 pointer-events-none rounded-bl-[33px] rounded-br-[33px]"
                  style={{
                    background:
                      "linear-gradient(to top, #151515 50%, rgba(21, 21, 21, 1) 55%, rgba(21, 21, 21, 0.85) 60%, rgba(21, 21, 21, 0.7) 65%, rgba(21, 21, 21, 0.6) 70%, rgba(21, 21, 21, 0.3) 75%, rgba(21, 21, 21, 0.1) 90%, transparent 100%)",
                  }}
                />

                {/* Bottom Area */}
                <div className="absolute bottom-0 left-0 right-0 z-20 px-6 pb-6 flex flex-col gap-3">
                  {/* Generated Invite Display */}
                  <AnimatePresence>
                    {generatedInvite && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 10 }}
                        className="rounded-xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 p-3"
                        style={{
                          background:
                            "linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(16, 185, 129, 0.03) 100%), #151515",
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-medium text-white">
                              {copiedTitleTokenId === generatedInvite.id
                                ? "Invite link copied"
                                : "Invite link created"}
                            </h3>
                          </div>
                          <button
                            type="button"
                            onClick={() => setGeneratedInvite(null)}
                            className="p-1 rounded-md text-[#6a6a6a] hover:text-white hover:bg-white/5 transition-all"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        </div>

                        <div className="bg-[#0d0d0d] rounded-lg p-2.5 border border-[#2a2a2a] flex items-center gap-2">
                          <code className="text-[11px] text-emerald-400 break-all flex-1 font-mono">
                            {generatedInvite.link}
                          </code>
                          <motion.button
                            type="button"
                            onClick={() =>
                              handleCopyToken(
                                generatedInvite.link,
                                generatedInvite.id,
                              )
                            }
                            className="shrink-0 rounded-md bg-black/80 border border-emerald-500/60 p-2 hover:border-emerald-400 transition-colors"
                          >
                            <motion.div
                              key={`invite-copy-${invitePulse}`}
                              className="relative size-3.5"
                              initial={{ scale: 1, filter: "blur(0px)" }}
                              animate={{
                                scale: [1, 0.95, 1],
                                filter: ["blur(0px)", "blur(2px)", "blur(0px)"],
                              }}
                              transition={{
                                duration: 0.18,
                                ease: "easeOut",
                              }}
                            >
                              <motion.span
                                className="absolute inset-0 flex items-center justify-center"
                                initial={{
                                  opacity:
                                    copiedTokenId === generatedInvite.id
                                      ? 1
                                      : 0,
                                }}
                                animate={{
                                  opacity:
                                    copiedTokenId === generatedInvite.id
                                      ? 0
                                      : 1,
                                }}
                                transition={{ duration: 0.15, ease: "easeOut" }}
                              >
                                <Copy className="h-3.5 w-3.5 text-emerald-400" />
                              </motion.span>
                              <motion.span
                                className="absolute inset-0 flex items-center justify-center"
                                initial={{
                                  opacity:
                                    copiedTokenId === generatedInvite.id
                                      ? 0
                                      : 1,
                                }}
                                animate={{
                                  opacity:
                                    copiedTokenId === generatedInvite.id
                                      ? 1
                                      : 0,
                                }}
                                transition={{ duration: 0.15, ease: "easeOut" }}
                              >
                                <Check className="h-3.5 w-3.5 text-emerald-400" />
                              </motion.span>
                            </motion.div>
                          </motion.button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Generated Reset Link Display */}
                  <AnimatePresence>
                    {generatedResetLink && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 10 }}
                        className="rounded-xl border border-[#0099bb]/20 p-3"
                        style={{
                          background:
                            "linear-gradient(135deg, rgba(0, 153, 187, 0.1) 0%, rgba(0, 153, 187, 0.03) 100%), #151515",
                        }}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <h3 className="text-sm font-medium text-white">
                              {copiedTitleTokenId === generatedResetLink.id
                                ? "Reset link copied"
                                : "Reset link created"}
                            </h3>
                          </div>
                          <button
                            type="button"
                            onClick={() => setGeneratedResetLink(null)}
                            className="p-1 rounded-md text-[#6a6a6a] hover:text-white hover:bg-white/5 transition-all"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        </div>

                        <div className="bg-[#0d0d0d] rounded-lg p-2.5 border border-[#2a2a2a] flex items-center gap-2">
                          <code className="text-[11px] text-[#0099bb] break-all flex-1 font-mono">
                            {generatedResetLink.link}
                          </code>
                          <motion.button
                            type="button"
                            onClick={() =>
                              handleCopyToken(
                                generatedResetLink.link,
                                generatedResetLink.id,
                              )
                            }
                            className="shrink-0 rounded-md bg-black/80 border border-[#0099bb]/70 p-2 hover:border-[#00b1d4] transition-colors"
                          >
                            <motion.div
                              key={`reset-copy-${resetPulse}`}
                              className="relative size-3.5"
                              initial={{ scale: 1, filter: "blur(0px)" }}
                              animate={{
                                scale: [1, 0.95, 1],
                                filter: ["blur(0px)", "blur(2px)", "blur(0px)"],
                              }}
                              transition={{
                                duration: 0.18,
                                ease: "easeOut",
                              }}
                            >
                              <motion.span
                                className="absolute inset-0 flex items-center justify-center"
                                initial={{
                                  opacity:
                                    copiedTokenId === generatedResetLink.id
                                      ? 1
                                      : 0,
                                }}
                                animate={{
                                  opacity:
                                    copiedTokenId === generatedResetLink.id
                                      ? 0
                                      : 1,
                                }}
                                transition={{ duration: 0.15, ease: "easeOut" }}
                              >
                                <Copy className="h-3.5 w-3.5 text-[#00b1d4]" />
                              </motion.span>
                              <motion.span
                                className="absolute inset-0 flex items-center justify-center"
                                initial={{
                                  opacity:
                                    copiedTokenId === generatedResetLink.id
                                      ? 0
                                      : 1,
                                }}
                                animate={{
                                  opacity:
                                    copiedTokenId === generatedResetLink.id
                                      ? 1
                                      : 0,
                                }}
                                transition={{ duration: 0.15, ease: "easeOut" }}
                              >
                                <Check className="h-3.5 w-3.5 text-[#00b1d4]" />
                              </motion.span>
                            </motion.div>
                          </motion.button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Buttons */}
                  <div className="flex items-center gap-3">
                    <Button
                      className="flex-1 bg-gradient-to-b from-[#222222] to-[#1a1a1a] border border-[#3a3a3a] hover:border-[#4a4a4a] hover:from-[#2a2a2a] hover:to-[#222222] text-white rounded-xl h-11 shadow-lg shadow-black/20 scale-100"
                      onClick={handleCreateInvite}
                    >
                      <Plus className="size-4" />
                      <span className="text-sm font-medium">Invite User</span>
                    </Button>
                    <Button
                      onClick={onClose}
                      className="flex-1 bg-gradient-to-b from-[#3a3a3a] to-[#2a2a2a] hover:from-[#444444] hover:to-[#333333] text-white border border-[#4a4a4a] rounded-xl h-11 shadow-lg shadow-black/20 scale-100"
                    >
                      <span className="text-sm font-medium">Done</span>
                    </Button>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Delete User Confirmation Modal */}
      <DeleteUserModal
        isOpen={deleteConfirmingUser !== null}
        onClose={() => setDeleteConfirmingUser(null)}
        onConfirm={handleConfirmDelete}
        user={deleteConfirmingUser}
        isDeleting={deleteUserMutation.isPending}
      />
    </>,
    document.body,
  );
}

interface UserCardProps {
  user: adminApi.UserResponse;
  currentUser: any;
  onToggleAdmin: () => void;
  onDelete: () => void;
  onCreateResetLink: () => void;
  onRenameClick: () => void;
  renamingUserId: number | null;
  newUsername: string;
  onRenameChange: (value: string) => void;
  onRenameSave: () => void;
  onRenameCancel: () => void;
  isDeleteMutating: boolean;
  isUpdateRoleMutating: boolean;
  isCreateResetMutating: boolean;
}

function UserCard({
  user,
  currentUser,
  onToggleAdmin,
  onDelete,
  onCreateResetLink,
  onRenameClick,
  renamingUserId,
  newUsername,
  onRenameChange,
  onRenameSave,
  onRenameCancel,
  isDeleteMutating,
  isUpdateRoleMutating,
  isCreateResetMutating,
}: UserCardProps) {
  const hasFocusedRef = useRef(false);
  const pendingRenameRef = useRef(false);
  const canChangeAdminRole =
    currentUser?.is_owner && currentUser?.id !== user.id && !user.is_owner;
  const canPerformActions = !(user.is_owner && !currentUser?.is_owner);
  const isCurrentUser = currentUser?.id === user.id;
  const isRenaming = renamingUserId === user.id;

  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isRenaming) {
      hasFocusedRef.current = false;
      pendingRenameRef.current = false;
      return;
    }
    // setTimeout(0) runs after all pending rAFs, including Radix UI's
    // focus-restoration rAF that fires when the dropdown closes.
    const id = setTimeout(() => {
      if (inputRef.current) {
        const len = inputRef.current.value.length;
        inputRef.current.focus();
        inputRef.current.setSelectionRange(len, len);
        hasFocusedRef.current = true;
      }
    }, 0);
    return () => clearTimeout(id);
  }, [isRenaming]);

  const handleRenameMenuClick = () => {
    pendingRenameRef.current = true;
    onRenameClick();
  };

  return (
    <div className="flex items-center justify-between gap-3 px-3 py-2.5 min-h-[57px] hover:bg-white/5 transition-colors first:rounded-t-xl last:rounded-b-xl">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <div className="relative min-w-0">
            {/* Always rendered for stable layout sizing */}
            <span
              className={`text-base font-medium block whitespace-pre ${isRenaming ? "invisible" : "text-white truncate"}`}
            >
              {isRenaming ? newUsername : user.username}
            </span>
            {isRenaming && (
              <input
                ref={inputRef}
                type="text"
                value={newUsername}
                onChange={(e) => onRenameChange(e.target.value)}
                className="absolute inset-0 text-base font-medium text-white bg-transparent border-none outline-none focus:outline-none w-full"
                style={{ caretColor: "white" }}
                onBlur={() => {
                  if (!hasFocusedRef.current) return;
                  if (newUsername.trim() && newUsername !== user.username) {
                    onRenameSave();
                  } else {
                    onRenameCancel();
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.currentTarget.blur();
                  } else if (e.key === "Escape") {
                    onRenameCancel();
                  }
                }}
              />
            )}
          </div>
          <div
            className={`flex items-center gap-2 shrink-0 transition-opacity duration-150 ${isRenaming ? "opacity-0" : "opacity-100"}`}
          >
            {isCurrentUser && (
              <span className="text-xs text-[#0099bb]">(you)</span>
            )}
            {user.is_admin && (
              <div
                className="px-2 py-0.5 bg-[#151414] border border-[#595959] rounded-md text-[10px] text-white"
                style={{
                  fontFamily: '"IBM Plex Mono", monospace',
                  fontWeight: 300,
                }}
              >
                Admin
              </div>
            )}
            {user.is_owner && (
              <div
                className="px-2 py-0.5 bg-[#2a1515] border border-red-500/30 rounded-md text-[10px] text-red-400"
                style={{
                  fontFamily: '"IBM Plex Mono", monospace',
                  fontWeight: 300,
                }}
              >
                Owner
              </div>
            )}
          </div>
        </div>
        <div className="text-sm text-muted-foreground truncate">
          {user.email}
        </div>
      </div>

      {/* Actions */}
      {canPerformActions ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="p-2 rounded-xl hover:bg-white/5 transition-colors shrink-0"
            >
              <MoreVertical className="size-4 text-muted-foreground" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="w-52 bg-[#1a1a1a] border-[#2a2a2a] rounded-xl z-1100"
            onCloseAutoFocus={(e) => {
              if (pendingRenameRef.current) e.preventDefault();
            }}
          >
            {isCurrentUser && (
              <DropdownMenuItem
                onClick={handleRenameMenuClick}
                className="text-white hover:bg-white/5 cursor-pointer rounded-lg mx-1"
              >
                <Pencil className="size-4 mr-2 text-[#6a6a6a]" />
                Rename
              </DropdownMenuItem>
            )}

            {canChangeAdminRole && (
              <DropdownMenuItem
                onClick={onToggleAdmin}
                disabled={isUpdateRoleMutating}
                className="text-white hover:bg-white/5 cursor-pointer rounded-lg mx-1"
              >
                {user.is_admin ? (
                  <>
                    <ShieldAlert className="size-4 mr-2 text-[#6a6a6a]" />
                    Remove Admin
                  </>
                ) : (
                  <>
                    <Shield className="size-4 mr-2 text-[#6a6a6a]" />
                    Make Admin
                  </>
                )}
              </DropdownMenuItem>
            )}

            <DropdownMenuItem
              onClick={onCreateResetLink}
              disabled={isCreateResetMutating}
              className="text-white hover:bg-white/5 cursor-pointer rounded-lg mx-1"
            >
              <RotateCcw className="size-4 mr-2 text-[#6a6a6a]" />
              {isCreateResetMutating ? "Generating..." : "Reset Password"}
            </DropdownMenuItem>

            {!user.is_owner && (
              <>
                <DropdownMenuSeparator className="bg-[#2a2a2a] my-1" />
                <DropdownMenuItem
                  onClick={onDelete}
                  disabled={isDeleteMutating}
                  variant="destructive"
                  className="cursor-pointer rounded-lg mx-1"
                >
                  <Trash2 className="size-4 mr-2" />
                  Delete User
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : (
        <div className="w-8" />
      )}
    </div>
  );
}
