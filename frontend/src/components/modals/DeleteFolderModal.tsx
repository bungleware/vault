import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";

interface DeleteFolderModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  folderName: string;
  itemCount: number;
  isDeleting?: boolean;
}

export default function DeleteFolderModal({
  isOpen,
  onClose,
  onConfirm,
  folderName,
  itemCount,
  isDeleting = false,
}: DeleteFolderModalProps) {
  return (
    <BaseModal
      isOpen={isOpen}
      onClose={onClose}
      disableClose={isDeleting}
      dataAttributes={{
        "data-modal-backdrop": "true",
        "data-modal-container": "true",
        "data-modal-content": "true",
      }}
    >
      <div className="p-6 md:p-8">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Delete Folder
        </h2>

        <p className="text-sm text-muted-foreground text-center mb-6">
          Are you sure you want to delete{" "}
          <span className="text-white font-medium">"{folderName}"</span>?{" "}
          {itemCount > 0 ? (
            <>
              {itemCount === 1
                ? "The project inside will be moved to the home."
                : `The ${itemCount} projects inside will be moved to the home.`}
            </>
          ) : (
            "This folder is empty."
          )}
        </p>

        <div className="flex flex-col gap-3">
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={isDeleting}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656]"
          >
            {isDeleting ? "Deleting..." : "Delete Folder"}
          </Button>
          <Button onClick={onClose} disabled={isDeleting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
