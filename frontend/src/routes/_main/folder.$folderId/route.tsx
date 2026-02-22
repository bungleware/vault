import { Outlet, createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/_main/folder/$folderId")({
  component: FolderLayout,
});

function FolderLayout() {
  return (
    <>
      <Outlet />
    </>
  );
}
