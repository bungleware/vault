import { AlertTriangle, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";
import { importInstance } from "@/api/instance";
import { useState, useRef } from "react";

interface ImportInstanceModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ImportInstanceModal({
  isOpen,
  onClose,
}: ImportInstanceModalProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (file: File) => {
    if (file.name.endsWith(".zip")) {
      setSelectedFile(file);
      setError(null);
    } else {
      setError("Please select a valid .zip backup file");
      setSelectedFile(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const handleImport = async () => {
    if (!selectedFile) return;

    try {
      setIsImporting(true);
      await importInstance(selectedFile);

      window.location.href = "/";
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to import backup";
      setError(message);
    } finally {
      setIsImporting(false);
    }
  };

  const isImportDisabled = !selectedFile || !isConfirmed || isImporting;

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isImporting} maxWidth="lg">
      <div className="p-6 md:p-8">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Import Instance
        </h2>

        <div
          className="rounded-2xl border border-red-500/30 p-4 mb-6"
          style={{
            background:
              "linear-gradient(0deg, #2a1515 0%, rgba(40, 20, 20, 0.3) 100%)",
          }}
        >
          <p
            className="text-sm text-red-400 font-light leading-relaxed text-center"
            style={{ fontFamily: '"IBM Plex Mono", monospace' }}
          >
            Importing will replace all current data. This action cannot be
            undone. We recommend exporting a backup first.
          </p>
        </div>

        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          className="border-2 border-dashed border-[#353333] rounded-lg p-8 mb-6 cursor-pointer hover:border-[#454545] transition-colors bg-[#191919]"
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".zip"
            onChange={handleFileInputChange}
            className="hidden"
          />

          <div className="flex flex-col items-center justify-center">
            <Upload className="w-8 h-8 text-[#848484] mb-3" />
            <p className="text-white text-center mb-1">
              {selectedFile
                ? selectedFile.name
                : "Drag and drop backup file here"}
            </p>
            {!selectedFile && (
              <p className="text-sm text-[#848484]">or click to select</p>
            )}
          </div>
        </div>

        {error && (
          <p className="text-sm text-[#ff5656] text-center mb-4 bg-[#2a1a1a] p-3 rounded">
            {error}
          </p>
        )}

        <label className="flex items-center justify-center gap-3 mb-6 cursor-pointer">
          <input
            type="checkbox"
            checked={isConfirmed}
            onChange={(e) => setIsConfirmed(e.target.checked)}
            className="w-4 h-4 rounded"
            disabled={isImporting}
          />
          <span className="text-sm text-[#848484]">
            I understand this will replace all current data
          </span>
        </label>

        <div className="flex flex-col gap-3">
          <Button
            onClick={handleImport}
            disabled={isImportDisabled}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656] font-medium disabled:opacity-50"
          >
            {isImporting ? "Importing..." : "Import"}
          </Button>
          <Button onClick={onClose} disabled={isImporting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
