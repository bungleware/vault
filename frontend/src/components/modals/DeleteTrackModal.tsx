import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";

interface DeleteTrackModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  trackName: string;
  isDeleting?: boolean;
}

export default function DeleteTrackModal({
  isOpen,
  onClose,
  onConfirm,
  trackName,
  isDeleting = false,
}: DeleteTrackModalProps) {
  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isDeleting}>
      <div className="p-6 md:p-8 space-y-6">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <div className="text-center space-y-3">
          <h2 className="text-2xl font-semibold text-white">Delete Track</h2>
          <p className="text-sm text-muted-foreground">
            Are you absolutely sure you want to delete{" "}
            <span className="text-white font-medium">
              &ldquo;{trackName}&rdquo;
            </span>
            ? This action cannot be undone and will remove all versions and
            cached files for this track.
          </p>
        </div>

        <div className="space-y-3">
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={isDeleting}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656]"
          >
            {isDeleting ? "Deleting..." : "Delete track"}
          </Button>
          <Button onClick={onClose} disabled={isDeleting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
