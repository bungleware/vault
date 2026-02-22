declare module 'react-color-extractor' {
  import { ReactNode } from 'react';

  export interface ColorExtractorProps {
    /**
     * Callback function that receives the extracted colors
     */
    getColors?: (colors: string[]) => void;

    /**
     * Maximum number of colors to extract
     */
    maxColors?: number;

    /**
     * Error callback
     */
    onError?: (error: Error) => void;

    /**
     * Child element - typically an img element
     */
    children: ReactNode;
  }

  export const ColorExtractor: React.FC<ColorExtractorProps>;
}
