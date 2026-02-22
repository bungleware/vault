import { useState, useEffect, useLayoutEffect, useRef } from "react";
import { useUpdateProject } from "@/hooks/useProjects";
import { toast } from "@/routes/__root";

interface ProjectData {
  public_id: string;
  name: string;
  author_override?: string | null;
}

interface UseProjectEditingOptions {
  project: ProjectData | undefined;
  username: string | undefined;
  sharedByUsername: string | undefined;
}

export function useProjectEditing({
  project,
  username,
  sharedByUsername,
}: UseProjectEditingOptions) {
  const updateProject = useUpdateProject();
  const titleInputRef = useRef<HTMLInputElement>(null);
  const authorInputRef = useRef<HTMLInputElement>(null);
  const authorMeasureRef = useRef<HTMLSpanElement>(null);

  const [projectName, setProjectName] = useState("");
  const [projectAuthor, setProjectAuthor] = useState("");
  const [authorInputWidth, setAuthorInputWidth] = useState(0);
  const [isEditingAuthor, setIsEditingAuthor] = useState(false);
  const isSavingAuthor = useRef(false);

  useEffect(() => {
    if (project && !isEditingAuthor && !isSavingAuthor.current) {
      setProjectName(project.name);
      if (project.author_override && project.author_override.length > 0) {
        setProjectAuthor(project.author_override);
      } else if (sharedByUsername) {
        setProjectAuthor(sharedByUsername);
      } else {
        setProjectAuthor(username || "");
      }
    }
  }, [
    project?.public_id,
    project?.name,
    project?.author_override,
    username,
    sharedByUsername,
    isEditingAuthor,
  ]);

  useLayoutEffect(() => {
    if (authorMeasureRef.current) {
      const width = authorMeasureRef.current.offsetWidth;
      setAuthorInputWidth(width);
    }
  }, [projectAuthor, username, project]);

  useEffect(() => {
    const handleRenameEvent = () => {
      setTimeout(() => {
        if (titleInputRef.current) {
          const input = titleInputRef.current;
          input.focus();
          requestAnimationFrame(() => {
            if (titleInputRef.current) {
              const length = titleInputRef.current.value.length;
              titleInputRef.current.setSelectionRange(length, length);
            }
          });
        }
      }, 200);
    };

    window.addEventListener("project-rename", handleRenameEvent);
    return () =>
      window.removeEventListener("project-rename", handleRenameEvent);
  }, []);

  const handleSaveProjectName = async () => {
    if (!project || projectName === project.name) return;

    try {
      await updateProject.mutateAsync({
        id: project.public_id,
        data: { name: projectName },
      });
    } catch (_error) {
      toast.error("Failed to update project name");
      setProjectName(project.name);
    }
  };

  const handleSaveProjectAuthor = async () => {
    if (!project) return;

    isSavingAuthor.current = true;
    const trimmed = projectAuthor.trim();
    const currentAuthor = project.author_override ?? "";
    const defaultAuthor = username || "";

    const valueToSave = trimmed === "" ? defaultAuthor : trimmed;

    if (valueToSave === defaultAuthor) {
      if (currentAuthor) {
        try {
          await updateProject.mutateAsync({
            id: project.public_id,
            data: { author_override: "" } as any,
          });
          setProjectAuthor(defaultAuthor);
        } catch (_error) {
          toast.error("Failed to update author");
          setProjectAuthor(currentAuthor);
        } finally {
          setTimeout(() => {
            isSavingAuthor.current = false;
          }, 500);
        }
      } else {
        isSavingAuthor.current = false;
      }
      return;
    }

    if (valueToSave === currentAuthor) {
      isSavingAuthor.current = false;
      return;
    }

    try {
      await updateProject.mutateAsync({
        id: project.public_id,
        data: { author_override: valueToSave },
      });
    } catch (_error) {
      toast.error("Failed to update author");
      if (currentAuthor) {
        setProjectAuthor(currentAuthor);
      } else {
        setProjectAuthor(defaultAuthor);
      }
    } finally {
      setTimeout(() => {
        isSavingAuthor.current = false;
      }, 500);
    }
  };

  return {
    projectName,
    setProjectName,
    projectAuthor,
    setProjectAuthor,
    authorInputWidth,
    isEditingAuthor,
    setIsEditingAuthor,
    titleInputRef,
    authorInputRef,
    authorMeasureRef,
    handleSaveProjectName,
    handleSaveProjectAuthor,
  };
}
