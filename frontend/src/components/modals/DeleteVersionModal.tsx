import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";

interface DeleteVersionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  versionName: string;
  isDeleting?: boolean;
}

export default function DeleteVersionModal({
  isOpen,
  onClose,
  onConfirm,
  versionName,
  isDeleting = false,
}: DeleteVersionModalProps) {
  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isDeleting}>
      <div className="p-6 md:p-8 space-y-6">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <div className="text-center space-y-3">
          <h2 className="text-2xl font-semibold text-white">Delete Version</h2>
          <p className="text-sm text-muted-foreground">
            Deleting version{" "}
            <span className="text-white font-medium">
              &ldquo;{versionName}&rdquo;
            </span>{" "}
            will permanently remove its audio files from disk. This action
            cannot be undone.
          </p>
        </div>

        <div className="space-y-3">
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={isDeleting}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656]"
          >
            {isDeleting ? "Deleting..." : "Delete version"}
          </Button>
          <Button onClick={onClose} disabled={isDeleting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
