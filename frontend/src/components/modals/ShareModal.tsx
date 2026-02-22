import { useState, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "motion/react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ChevronLeft,
  Lock,
  Globe,
  Copy,
  Check,
  Eye,
  EyeOff,
  Users,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { toast } from "@/routes/__root";
import { useAuth } from "@/contexts/AuthContext";
import { getCSRFToken } from "@/api/client";
import type { VisibilityStatus, ShareToken } from "@/types/api";
import {
  createTrackShare,
  createProjectShare,
  updateTrackShare,
  updateProjectShare,
  updateTrackVisibility,
  updateProjectVisibility,
  listTrackShares,
  listProjectShares,
  deleteTrackShare,
  deleteProjectShare,
  updateProjectSharePermissions,
  updateTrackSharePermissions,
} from "@/api/sharing";
import { projectKeys } from "@/hooks/useProjects";
import { trackKeys } from "@/hooks/useTracks";
import {
  useAllUsers,
  useProjectShareUsers,
  useTrackShareUsers,
  sharingKeys,
} from "@/hooks/useSharing";

interface ShareModalProps {
  isOpen: boolean;
  onClose: () => void;
  onBack?: () => void;
  resourceType: "track" | "project";
  resourceId: string;
  resourceName: string;
  currentVisibility?: VisibilityStatus;
  onUpdate?: () => void;
  showBackdrop?: boolean;
  isOwned?: boolean;
}

type ModalView = "closed" | "main";

interface SharedUser {
  id: number;
  shared_to: number;
  can_edit: boolean;
  can_download: boolean;
  username?: string;
  email?: string;
}

const visibilityModes = [
  {
    value: "private" as const,
    icon: Lock,
    label: "Private",
    description: "Only you can access",
  },
  {
    value: "public" as const,
    icon: Globe,
    label: "Public",
    description: "Anyone with the link",
  },
];

export default function ShareModal({
  isOpen,
  onClose,
  onBack,
  resourceType,
  resourceId,
  resourceName,
  currentVisibility = "private",
  onUpdate,
  showBackdrop = false,
  isOwned = true,
}: ShareModalProps) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [modalView, setModalView] = useState<ModalView>("closed");
  const [visibility, setVisibility] =
    useState<VisibilityStatus>(currentVisibility);
  const [allowEditing, setAllowEditing] = useState(false);
	const [allowDownloads, setAllowDownloads] = useState(false);
  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [currentShareLink, setCurrentShareLink] = useState<ShareToken | null>(
    null,
  );
  const [, setIsLoadingShare] = useState(false);
  const [isResettingShare, setIsResettingShare] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [userSearchQuery, setUserSearchQuery] = useState("");
  const closeTimeoutRef = useRef<number | null>(null);
  const [pendingAction, setPendingAction] = useState<"close" | "back" | null>(
    null,
  );
  const [sharedUserIdsSnapshot, setSharedUserIdsSnapshot] = useState<
    Set<number>
  >(new Set());

  // Use React Query hooks for data fetching
  const { data: allUsers = [] } = useAllUsers();
  const { data: projectShares = [] } = useProjectShareUsers(
    resourceType === "project" && isOwned ? resourceId : undefined,
  );
  const { data: trackShares = [] } = useTrackShareUsers(
    resourceType === "track" && isOwned ? resourceId : undefined,
  );

  // Combine and enrich shares based on resource type
  const rawShares = resourceType === "project" ? projectShares : trackShares;
  const sharedUsers: SharedUser[] = rawShares.map((share) => {
    const user = allUsers.find((u) => u.id === share.shared_to);
    return {
      ...share,
      username: user?.username,
      email: user?.email,
    };
  });

  const handleShareToggle = async (userId: number, shouldShare: boolean) => {
    try {
      if (shouldShare) {
        const endpoint =
          resourceType === "track"
            ? `/api/tracks/${resourceId}/share-with-users`
            : `/api/projects/${resourceId}/share-with-users`;

        const response = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(getCSRFToken() ? { "X-CSRF-Token": getCSRFToken() as string } : {}),
          },
          credentials: "include",
          body: JSON.stringify({
            user_ids: [userId],
            can_edit: allowEditing,
            can_download: false,
          }),
        });

        if (!response.ok) {
          throw new Error("Failed to share with user");
        }
      } else {
        const share = sharedUsers.find((s) => s.shared_to === userId);
        if (!share) return;

        const endpoint =
          resourceType === "project"
            ? `/api/user-shares/projects/${share.id}`
            : `/api/user-shares/tracks/${share.id}`;

        const response = await fetch(endpoint, {
          method: "DELETE",
          headers: {
            ...(getCSRFToken() ? { "X-CSRF-Token": getCSRFToken() as string } : {}),
          },
          credentials: "include",
        });

        if (!response.ok) {
          throw new Error("Failed to unshare");
        }
      }

      // Invalidate queries to refetch data
      queryClient.invalidateQueries({ queryKey: sharingKeys.all });
      if (resourceType === "project") {
        queryClient.invalidateQueries({
          queryKey: projectKeys.detail(resourceId),
        });
        queryClient.invalidateQueries({ queryKey: projectKeys.lists() });
      } else {
        queryClient.invalidateQueries({
          queryKey: trackKeys.detail(resourceId),
        });
        queryClient.invalidateQueries({ queryKey: trackKeys.lists() });
      }
    } catch (error) {
      toast.error(
        shouldShare ? "Failed to share with user" : "Failed to unshare",
      );
    }
  };

  const handlePermissionChange = async (
    shareId: number,
    canEdit: boolean,
    canDownload: boolean,
  ) => {
    // Optimistically update the cache so switches don't flicker
    const queryKey =
      resourceType === "project"
        ? sharingKeys.projectShareUsers(resourceId)
        : sharingKeys.trackShareUsers(resourceId);

    queryClient.setQueryData(queryKey, (old: typeof rawShares | undefined) =>
      old?.map((share) =>
        share.id === shareId
          ? { ...share, can_edit: canEdit, can_download: canDownload }
          : share,
      ),
    );

    try {
      if (resourceType === "project") {
        await updateProjectSharePermissions(shareId, {
          can_edit: canEdit,
          can_download: canDownload,
        });
      } else {
        await updateTrackSharePermissions(shareId, {
          can_edit: canEdit,
          can_download: canDownload,
        });
      }
    } catch (error) {
      // Revert on failure
      queryClient.invalidateQueries({ queryKey });
      toast.error("Failed to update permissions");
    }
  };

  // Set snapshot only once when modal opens (not on subsequent updates)
  useEffect(() => {
    if (isOpen) {
      // Capture the initial snapshot for stable sorting
      setSharedUserIdsSnapshot(new Set(sharedUsers.map((s) => s.shared_to)));

      // Set default values from initial shared users
      if (sharedUsers.length > 0) {
        const allCanDownload = sharedUsers.every((s) => s.can_download);
        const allCanEdit = sharedUsers.every((s) => s.can_edit);
        setAllowDownloads(allCanDownload);
        setAllowEditing(allCanEdit);
      }
    }
    // Only run when modal opens, not when sharedUsers updates
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  useEffect(() => {
    if (isOpen) {
      if (closeTimeoutRef.current !== null) {
        clearTimeout(closeTimeoutRef.current);
        closeTimeoutRef.current = null;
      }
      setModalView("main");
      setVisibility(currentVisibility);
      loadCurrentShareLink(currentVisibility);
    } else {
      setModalView("closed");
    }
  }, [isOpen, currentVisibility]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        handleClose();
      }
    };

    if (modalView !== "closed") {
      document.addEventListener("keydown", handleEscape);
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [modalView]);

  useEffect(() => {
    return () => {
      if (closeTimeoutRef.current !== null) {
        clearTimeout(closeTimeoutRef.current);
      }
    };
  }, []);

  const handleClose = () => {
    setPendingAction("close");
    setModalView("closed");
  };

  const handleBack = () => {
    setPendingAction("back");
    setModalView("closed");
  };

  const loadCurrentShareLink = async (
    visibilityToCheck?: VisibilityStatus,
  ): Promise<ShareToken | null> => {
    const checkVisibility = visibilityToCheck ?? visibility;
    if (checkVisibility === "private") {
      setCurrentShareLink(null);
      return null;
    }

    setIsLoadingShare(true);
    try {
      const shares =
        resourceType === "track"
          ? await listTrackShares()
          : await listProjectShares();

      const currentShare = shares.find((share) => {
        if (resourceType === "track") {
          return share.track_public_id === resourceId;
        } else {
          return share.project_public_id === resourceId;
        }
      });

      if (currentShare) {
        setCurrentShareLink(currentShare);
        setAllowEditing(currentShare.allow_editing);
        setAllowDownloads(currentShare.allow_downloads);
        if (currentShare.has_password) {
          setUsePassword(true);
        }
        return currentShare;
      } else {
        setCurrentShareLink(null);
        return null;
      }
    } catch (error) {
      console.error("Failed to load share link:", error);
      return null;
    } finally {
      setIsLoadingShare(false);
    }
  };

  const handleVisibilityChange = async (newVisibility: VisibilityStatus) => {
    try {
      const updateData = {
        visibility_status: newVisibility,
        allow_editing: allowEditing,
        allow_downloads: allowDownloads,
        password: usePassword && password ? password : undefined,
      };

      if (resourceType === "track") {
        await updateTrackVisibility(resourceId, updateData);
      } else {
        await updateProjectVisibility(resourceId, updateData);
      }

      if (newVisibility !== "private") {
        const existingShare = await loadCurrentShareLink(newVisibility);
        if (!existingShare) {
          await handleCreateShare(newVisibility);
        }
      } else if (newVisibility === "private" && currentShareLink) {
        await handleDeleteShare();
      }

      setVisibility(newVisibility);
      onUpdate?.();
    } catch (error) {
      toast.error("Failed to update visibility");
      console.error("Failed to update visibility:", error);
    }
  };

  const handleUpdateShareAttributes = async (overrides?: {
    allowEditing?: boolean;
    allowDownloads?: boolean;
    password?: string | undefined;
  }) => {
    if (!currentShareLink) return;

    setIsResettingShare(true);
    try {
      const updateData: any = {
        allow_editing: overrides?.allowEditing ?? allowEditing,
        allow_downloads: overrides?.allowDownloads ?? allowDownloads,
        password:
          overrides && "password" in overrides
            ? overrides.password
            : usePassword && password
              ? password
              : undefined,
      };

      if (resourceType === "track") {
        const updated = await updateTrackShare(currentShareLink.id, updateData);
        setCurrentShareLink(updated);
      } else {
        const updated = await updateProjectShare(
          currentShareLink.id,
          updateData,
        );
        setCurrentShareLink(updated);
      }
    } catch (error) {
      toast.error("Failed to update share link");
      console.error("Failed to update share:", error);
    } finally {
      setIsResettingShare(false);
    }
  };

  const handleCreateShare = async (visibilityOverride?: VisibilityStatus) => {
    const effectiveVisibility = visibilityOverride ?? visibility;

    if (effectiveVisibility === "private") {
      return;
    }

    setIsResettingShare(true);
    try {
      const shareData: any = {
        allow_editing: allowEditing,
        allow_downloads: allowDownloads,
        password: usePassword && password ? password : undefined,
        visibility_type:
          effectiveVisibility === "public" ? "public" : "invite_only",
      };

      let newShare: ShareToken;
      if (resourceType === "track") {
        newShare = await createTrackShare(resourceId, shareData);
      } else {
        newShare = await createProjectShare(resourceId, shareData);
      }

      setCurrentShareLink(newShare);
    } catch (error) {
      toast.error("Failed to create share link");
      console.error("Failed to create share:", error);
    } finally {
      setIsResettingShare(false);
    }
  };

  const handleResetShare = async (visibilityOverride?: VisibilityStatus) => {
    const effectiveVisibility = visibilityOverride ?? visibility;

    if (effectiveVisibility === "private") {
      return;
    }

    setIsResettingShare(true);
    try {
      if (currentShareLink) {
        if (resourceType === "track") {
          await deleteTrackShare(currentShareLink.id);
        } else {
          await deleteProjectShare(currentShareLink.id);
        }
      }

      const shareData: any = {
        allow_editing: allowEditing,
        allow_downloads: allowDownloads,
        password: usePassword && password ? password : undefined,
        visibility_type:
          effectiveVisibility === "public" ? "public" : "invite_only",
      };

      let newShare: ShareToken;
      if (resourceType === "track") {
        newShare = await createTrackShare(resourceId, shareData);
      } else {
        newShare = await createProjectShare(resourceId, shareData);
      }

      setCurrentShareLink(newShare);
    } catch (error) {
      toast.error("Failed to reset share link");
      console.error("Failed to reset share:", error);
    } finally {
      setIsResettingShare(false);
    }
  };

  const handleDeleteShare = async () => {
    if (!currentShareLink) return;

    try {
      if (resourceType === "track") {
        await deleteTrackShare(currentShareLink.id);
      } else {
        await deleteProjectShare(currentShareLink.id);
      }
      setCurrentShareLink(null);
    } catch (error) {
      toast.error("Failed to delete share link");
      console.error("Failed to delete share:", error);
    }
  };

  const handleCopyLink = async () => {
    if (!currentShareLink) return;

    try {
      const urlToCopy = getShareUrl();
      await navigator.clipboard.writeText(urlToCopy);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch (error) {
      toast.error("Failed to copy link");
      console.error("Failed to copy:", error);
    }
  };

  const getShareUrl = () => {
    if (!currentShareLink) return "";

    if (visibility === "invite_only") {
      return currentShareLink.share_url.replace("/share/", "/invite/");
    }
    return currentShareLink.share_url;
  };

  return createPortal(
    <>
      <AnimatePresence>
        {modalView !== "closed" && showBackdrop && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-1000 bg-black/80"
            onClick={handleClose}
          />
        )}
      </AnimatePresence>

      <AnimatePresence
        onExitComplete={() => {
          if (modalView === "closed" && pendingAction) {
            setUsePassword(false);
            setPassword("");
            setShowPassword(false);
            setUserSearchQuery("");

            if (pendingAction === "close") {
              onClose();
            } else if (pendingAction === "back") {
              if (onBack) {
                onBack();
              } else {
                onClose();
              }
            }
            setPendingAction(null);
          }
        }}
      >
        {modalView === "main" && (
          <motion.div
            key="share-modal"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-1000 flex items-center justify-center p-4 pointer-events-none"
          >
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.15 }}
              className="relative z-10 w-full max-w-2xl border border-[#292828] rounded-[34px] shadow-2xl overflow-hidden pointer-events-auto max-h-[90vh] flex flex-col"
              style={{
                background: "linear-gradient(0deg, #151515 0%, #1D1D1D 100%)",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="p-6 overflow-y-auto flex-1">
                <div className="flex items-center gap-4 mb-6">
                  <Button size="icon-lg" onClick={handleBack}>
                    <ChevronLeft className="size-5" />
                  </Button>
                  <div className="flex-1 min-w-0">
                    <h2
                      className="text-xl font-light text-white"
                      style={{
                        fontFamily: '"IBM Plex Mono", monospace',
                      }}
                    >
                      Share
                    </h2>
                    <p className="text-lg text-muted-foreground mt-0.5 truncate">
                      {resourceName}
                    </p>
                  </div>
                </div>

                <div className="mb-6">
                  <Label className="text-sm text-muted-foreground mb-3 block">
                    Who can access
                  </Label>
                  <div className="relative flex w-full p-1 rounded-xl border border-white/10 bg-white/5">
                    {visibilityModes.map((mode) => {
                      const Icon = mode.icon;
                      const isActive = visibility === mode.value;

                      return (
                        <button
                          key={mode.value}
                          onClick={() => handleVisibilityChange(mode.value)}
                          title={mode.description}
                          className={cn(
                            "relative z-10 flex-1 px-4 py-2 rounded-lg transition-colors duration-200",
                            "flex flex-row items-center justify-center gap-2 min-w-0",
                            isActive
                              ? "text-white"
                              : "text-muted-foreground hover:text-white/80",
                          )}
                        >
                          <Icon className="size-4 shrink-0" />
                          <span className="text-sm font-medium">
                            {mode.label}
                          </span>
                        </button>
                      );
                    })}
                    <motion.div
                      layoutId="visibility-toggle-indicator"
                      className="absolute top-1 bottom-1 rounded-lg bg-white/15 z-0"
                      initial={false}
                      animate={{
                        left: visibility === "private" ? 4 : "calc(50% + 2px)",
                        width: "calc(50% - 6px)",
                      }}
                      transition={{ type: "spring", bounce: 0, duration: 0.25 }}
                    />
                  </div>
                </div>

                <div className="p-4 rounded-2xl border border-white/10 bg-white/5">
                  <div className="flex items-center gap-2 mb-3 ml-1">
                    <Users className="size-4 text-muted-foreground" />
                    <Label className="text-sm text-muted-foreground">
                      Share with users in instance
                    </Label>
                  </div>

                  <div className="relative mb-3">
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
                        onClick={() => setUserSearchQuery("")}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-white transition-colors"
                      >
                        <X className="size-3.5" />
                      </button>
                    )}
                  </div>

                  <div className="h-43 overflow-y-auto rounded-xl border border-white/10 divide-y divide-white/5">
                    {(() => {
                      const availableUsers = allUsers
                        .filter((u) => {
                          if (user?.id && u.id === user.id) return false;
                          if (!userSearchQuery) return true;
                          const q = userSearchQuery.toLowerCase();
                          return (
                            u.username.toLowerCase().includes(q) ||
                            u.email.toLowerCase().includes(q)
                          );
                        })
                        .sort((a, b) => {
                          const aIsShared = sharedUserIdsSnapshot.has(a.id);
                          const bIsShared = sharedUserIdsSnapshot.has(b.id);

                          if (aIsShared && !bIsShared) return -1;
                          if (!aIsShared && bIsShared) return 1;
                          return 0;
                        });

                      if (availableUsers.length === 0) {
                        return (
                          <div className="px-4 py-6 text-center text-sm text-muted-foreground">
                            {userSearchQuery
                              ? "No users found"
                              : "No other users in instance"}
                          </div>
                        );
                      }

                      return availableUsers.map((u) => {
                        const sharedUser = sharedUsers.find(
                          (s) => s.shared_to === u.id,
                        );
                        const isShared = !!sharedUser;

                        return (
                          <div
                            key={u.id}
                            className="flex items-center justify-between gap-3 px-3 py-2.5 min-h-[57px] hover:bg-white/5 transition-colors"
                          >
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-white truncate">
                                @{u.username}
                              </div>
                              <div className="text-xs text-muted-foreground truncate">
                                {u.email}
                              </div>
                            </div>
                            {isShared ? (
                              <div className="flex items-center gap-2 shrink-0">
                                <div className="flex items-center gap-1">
                                  <Switch
                                    checked={sharedUser.can_download}
                                    onCheckedChange={(checked) => {
                                      handlePermissionChange(
                                        sharedUser.id,
                                        sharedUser.can_edit,
                                        checked,
                                      );
                                    }}
                                  />
                                  <span className="text-xs text-muted-foreground">
                                    Download
                                  </span>
                                </div>
                                <div className="flex items-center gap-1">
                                  <Switch
                                    checked={sharedUser.can_edit}
                                    onCheckedChange={(checked) => {
                                      handlePermissionChange(
                                        sharedUser.id,
                                        checked,
                                        sharedUser.can_download,
                                      );
                                    }}
                                  />
                                  <span className="text-xs text-muted-foreground">
                                    Edit
                                  </span>
                                </div>
                                <button
                                  onClick={() => handleShareToggle(u.id, false)}
                                  className="p-1 hover:bg-red-500/20 rounded transition-colors"
                                >
                                  <X className="size-4 text-red-400" />
                                </button>
                              </div>
                            ) : (
                              <button
                                onClick={() => handleShareToggle(u.id, true)}
                                className="px-3 py-1 text-xs bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors text-white whitespace-nowrap"
                              >
                                Share
                              </button>
                            )}
                          </div>
                        );
                      });
                    })()}
                  </div>
                </div>

                <AnimatePresence initial={false}>
                  {visibility !== "private" && (
                    <motion.div
                      key="share-settings"
                      initial={{ opacity: 0, height: 0, filter: "blur(4px)" }}
                      animate={{
                        opacity: 1,
                        height: "auto",
                        filter: "blur(0px)",
                      }}
                      exit={{ opacity: 0, height: 0, filter: "blur(4px)" }}
                      transition={{ type: "spring", bounce: 0, duration: 0.4 }}
                      className="overflow-hidden"
                    >
                      <div className="p-4 rounded-2xl border border-white/10 bg-white/5 mt-6">
						<div className="flex items-center gap-2 mb-4">
							<Globe className="size-4 text-muted-foreground" />
							<Label className="text-sm text-muted-foreground">
								Public Link
							</Label>
                          {currentShareLink?.has_password && (
                            <div className="flex items-center gap-1 text-xs text-muted-foreground">
                              <Lock className="size-3" />
                              <span>Password protected</span>
                            </div>
                          )}
                        </div>

                        {currentShareLink ? (
                          <div className="flex gap-2 mb-4">
                            <Input
                              type="text"
                              value={getShareUrl()}
                              readOnly
                              className="flex-1 text-white rounded-2xl text-sm"
                            />
                            <Button
                              size="icon"
                              variant="outline"
                              onClick={handleCopyLink}
                              title={copiedLink ? "Copied!" : "Copy link"}
                            >
                              {copiedLink ? (
                                <Check className="size-4" />
                              ) : (
                                <Copy className="size-4" />
                              )}
                            </Button>
                            <Button
                              size="icon"
                              variant="outline"
                              onClick={() => handleResetShare()}
                              disabled={isResettingShare}
                              title="Reset link"
                            >
                              <RefreshCw
                                className={cn(
                                  "size-4",
                                  isResettingShare && "animate-spin",
                                )}
                              />
                            </Button>
                          </div>
                        ) : (
                          <div className="mb-4">
                            <Button
                              onClick={() => handleCreateShare()}
                              disabled={isResettingShare}
                              className="w-full"
                            >
                              {isResettingShare
                                ? "Creating..."
                                : `Create ${visibility === "invite_only" ? "Invite" : "Share"} Link`}
                            </Button>
                          </div>
                        )}

                        {visibility === "public" && (
                          <div className="space-y-4 border-t border-white/10 pt-4">
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="text-sm font-medium text-white">
                                  Allow Downloads
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  Let others download files
                                </div>
                              </div>
                              <Switch
                                checked={allowDownloads}
                                onCheckedChange={async (checked) => {
                                  setAllowDownloads(checked);
                                  if (currentShareLink) {
                                    await handleUpdateShareAttributes({
                                      allowDownloads: checked,
                                    });
                                  }
                                }}
                              />
                            </div>

                            <div className="border-t border-white/10 pt-4">
                              <div className="flex items-center justify-between">
                                <div>
                                  <div className="text-sm font-medium text-white">
                                    Password Protection
                                  </div>
                                  <div className="text-xs text-muted-foreground">
                                    Require a password to access
                                  </div>
                                </div>
                                <Switch
                                  checked={usePassword}
                                  onCheckedChange={async (checked) => {
                                    setUsePassword(checked);
                                    if (!checked && currentShareLink) {
                                      setPassword("");
                                      await handleUpdateShareAttributes({
                                        password: undefined,
                                      });
                                    }
                                  }}
                                />
                              </div>
                              <AnimatePresence initial={false}>
                                {usePassword && (
                                  <motion.div
                                    key="password-input"
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{
                                      type: "spring",
                                      bounce: 0,
                                      duration: 0.3,
                                    }}
                                    className="overflow-hidden"
                                  >
                                    <div className="mt-3 flex gap-2">
                                      <div className="relative flex-1">
                                        <Input
                                          type={
                                            showPassword ? "text" : "password"
                                          }
                                          placeholder="Enter password"
                                          value={password}
                                          onChange={(e) =>
                                            setPassword(e.target.value)
                                          }
                                          className="pr-10 text-white rounded-2xl"
                                        />
                                        <button
                                          type="button"
                                          onClick={() =>
                                            setShowPassword(!showPassword)
                                          }
                                          className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-white"
                                        >
                                          {showPassword ? (
                                            <EyeOff className="size-4" />
                                          ) : (
                                            <Eye className="size-4" />
                                          )}
                                        </button>
                                      </div>
                                      {currentShareLink && (
                                        <Button
                                          size="sm"
                                          variant="outline"
                                          onClick={() =>
                                            handleUpdateShareAttributes()
                                          }
                                          disabled={
                                            isResettingShare || !password
                                          }
                                          className="h-9"
                                        >
                                          Update
                                        </Button>
                                      )}
                                    </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>
                            </div>
                          </div>
                        )}
                        {visibility === "invite_only" && (
                          <div className="text-sm text-muted-foreground border-t border-white/10 pt-4">
                            Invited users can view and add this {resourceType}{" "}
                            to their library. They will need to sign in to
                            accept the invitation.
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>,
    document.body,
  );
}
