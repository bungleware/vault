import {
  Outlet,
  createFileRoute,
  useNavigate,
  useRouterState,
} from "@tanstack/react-router";
import { Link } from "@tanstack/react-router";
import { useEffect, useMemo, useState, useRef } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { SearchIcon, UserIcon, ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useFolder, useAllFolders, useUpdateFolder } from "@/hooks/useFolders";
import type { Folder } from "@/types/api";
import { toast } from "@/routes/__root";
import GlobalSearchModal from "@/components/GlobalSearchModal";

export const Route = createFileRoute("/_main")({
  component: MainLayout,
});

function MainLayout() {
  const { isAuthenticated, isLoading } = useAuth();
  const navigate = useNavigate();
  const routerState = useRouterState();

  const isFolderRoute = routerState.location.pathname.startsWith("/folder/");
  const folderIdMatch = routerState.location.pathname.match(/^\/folder\/(\d+)/);
  const folderId = folderIdMatch ? parseInt(folderIdMatch[1], 10) : undefined;

  const { data: folder, isLoading: folderLoading } = useFolder(folderId);
  const { data: allFolders } = useAllFolders();
  const updateFolder = useUpdateFolder();

  const [folderName, setFolderName] = useState("");
  const folderNameInputRef = useRef<HTMLInputElement>(null);

  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const searchButtonRef = useRef<HTMLButtonElement>(null);

  const breadcrumb = useMemo(() => {
    if (!isFolderRoute || !folder || !allFolders) return [];

    const folderMap = new Map<number, Folder>();
    allFolders.forEach((f) => folderMap.set(f.id, f));

    const path: Folder[] = [];
    let currentFolder: Folder | undefined = folder;

    while (currentFolder) {
      path.unshift(currentFolder); // Add to beginning
      if (currentFolder.parent_id) {
        currentFolder = folderMap.get(currentFolder.parent_id);
      } else {
        break;
      }
    }

    return path;
  }, [isFolderRoute, folder, allFolders]);

  const handleBreadcrumbClick = (targetFolderId: number | null) => {
    if (targetFolderId === null) {
      navigate({ to: "/" });
    } else {
      navigate({
        to: "/folder/$folderId",
        params: { folderId: String(targetFolderId) },
      });
    }
  };

  const handleBack = () => {
    if (!folder) return;
    if (folder.parent_id) {
      navigate({
        to: "/folder/$folderId",
        params: { folderId: String(folder.parent_id) },
      });
    } else {
      navigate({ to: "/" });
    }
  };

  const folderDepth = breadcrumb.length;
  const isDeeplyNested = folderDepth >= 2;

  const isFolderNameSet = useMemo(() => {
    if (!folder) return false;
    if (!folder.name || !folder.name.trim()) return false;
    const createdAt = new Date(folder.created_at).getTime();
    const updatedAt = new Date(folder.updated_at).getTime();
    return Math.abs(updatedAt - createdAt) > 1000;
  }, [folder?.created_at, folder?.updated_at, folder?.name]);

  useEffect(() => {
    if (folder) {
      setFolderName(isFolderNameSet ? folder.name : "");
    }
  }, [folder?.id, folder?.name, isFolderNameSet]);

  const handleSaveFolderName = async () => {
    if (!folder || !folderId) return;

    const trimmedName = folderName.trim();

    const nameToSave = trimmedName || "New Folder";

    if (nameToSave === (folder.name || "").trim()) {
      if (!trimmedName) {
        setFolderName("New Folder");
      }
      return;
    }

    try {
      await updateFolder.mutateAsync({
        id: folderId,
        data: { name: nameToSave },
      });
      setFolderName(nameToSave);
    } catch (_error) {
      toast.error("Failed to update folder name");
      setFolderName(folder.name || "New Folder");
    }
  };

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate({ to: "/login", replace: true });
    }
  }, [isLoading, isAuthenticated, navigate]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.code === "KeyF") {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
        return;
      }

      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  if (isLoading || !isAuthenticated) {
    return <div className="min-h-screen bg-background" />;
  }

  return (
    <>
      <header className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between text-white md:p-10 p-6 gap-4">
        {isFolderRoute ? (
          isDeeplyNested ? (
            <div className="flex items-center gap-2 md:ml-4 ml-0.5 min-w-0 flex-1">
              <Button
                variant="ghost"
                size="sm"
                className="flex items-center gap-1 text-white hover:text-white/80 -ml-2"
                onClick={handleBack}
              >
                <ChevronLeft className="size-4" />
              </Button>
              {folderLoading ? (
                <span className="text-2xl font-medium">...</span>
              ) : (
                <input
                  ref={folderNameInputRef}
                  type="text"
                  tabIndex={0}
                  value={folderName}
                  onChange={(e) => setFolderName(e.target.value)}
                  onBlur={handleSaveFolderName}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.currentTarget.blur();
                    }
                  }}
                  className="text-2xl font-medium bg-transparent border-none p-0 m-0 h-auto outline-none text-white placeholder:text-white/50 focus:outline-none focus:ring-0 truncate"
                  placeholder="New Folder"
                />
              )}
            </div>
          ) : (
            <nav className="flex items-center gap-2 text-sm md:ml-4 ml-0.5 min-w-0 flex-1 overflow-x-auto">
              <Button
                variant="ghost"
                size="sm"
                className="h-auto p-0 text-white/50 hover:text-white text-2xl font-medium shrink-0"
                onClick={() => handleBreadcrumbClick(null)}
              >
                {"{ vault }"}
              </Button>
              {folderLoading ? (
                <>
                  <span className="text-white/50 text-2xl shrink-0">{" / "}</span>
                  <span className="text-white/70">...</span>
                </>
              ) : (
                breadcrumb.map((folderItem, _index) => {
                  const isCurrentFolder = folderItem.id === folder?.id;
                  return (
                    <span
                      key={folderItem.id}
                      className="flex items-center gap-2 min-w-0"
                    >
                      <span className="text-white/50 text-2xl shrink-0">{" / "}</span>
                      {isCurrentFolder ? (
                        <input
                          ref={folderNameInputRef}
                          type="text"
                          tabIndex={0}
                          value={folderName}
                          onChange={(e) => setFolderName(e.target.value)}
                          onBlur={handleSaveFolderName}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.currentTarget.blur();
                            }
                          }}
                          className="text-2xl font-medium bg-transparent border-none p-0 m-0 h-auto outline-none text-white placeholder:text-white/50 focus:outline-none focus:ring-0 truncate"
                          placeholder="New Folder"
                        />
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-auto p-0 text-white hover:text-white/80 text-2xl font-medium truncate"
                          onClick={() => handleBreadcrumbClick(folderItem.id)}
                        >
                          {folderItem.name}
                        </Button>
                      )}
                    </span>
                  );
                })
              )}
            </nav>
          )
        ) : (
          <h1 className="md:ml-4 ml-0.5 text-xl font-semibold">
            <Link to="/">
              <div className="text-2xl font-medium">{"{ vault }"}</div>
            </Link>
          </h1>
        )}
        <div className="flex items-center gap-2.5">
          {/* TODO: Implement notifications feature */}
          {/* <Button variant="default" size="icon-lg">
            <BellIcon fill="white" className="size-4.5"></BellIcon>
          </Button> */}
          <Button
            ref={searchButtonRef}
            variant="default"
            size="icon-lg"
            onClick={() => setIsSearchOpen(true)}
          >
            <SearchIcon strokeWidth={3} className="size-4.5"></SearchIcon>
          </Button>
          <Link to="/profile">
            <Button variant="default" size="icon-lg">
              <UserIcon fill="white" className="size-4.5"></UserIcon>
            </Button>
          </Link>
        </div>
      </header>
      <Outlet />

      <GlobalSearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
      />
    </>
  );
}
