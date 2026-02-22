import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";

interface DeleteProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  projectName: string;
  isDeleting?: boolean;
}

export default function DeleteProjectModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  isDeleting = false,
}: DeleteProjectModalProps) {
  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isDeleting}>
      <div className="p-6 md:p-8">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Delete Project
        </h2>

        <p className="text-sm text-muted-foreground text-center mb-6">
          Are you sure you want to delete{" "}
          <span className="text-white font-medium">"{projectName}"</span>? This
          action cannot be undone and will delete all tracks in this project.
        </p>

        <div className="flex flex-col gap-3">
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={isDeleting}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656]"
          >
            {isDeleting ? "Deleting..." : "Delete Project"}
          </Button>
          <Button onClick={onClose} disabled={isDeleting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
