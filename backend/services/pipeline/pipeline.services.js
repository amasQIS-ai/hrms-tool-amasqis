import { getTenantCollections } from "../../config/db.js";
import { ObjectId } from "mongodb";
import PDFDocument from "pdfkit";
import ExcelJS from "exceljs";
import fs from "fs";
import path from "path";
import { format } from "date-fns";

export const createPipeline = async (companyId, pipelineData) => {
  try {
    const collections = getTenantCollections(companyId);
    console.log("[PipelineService] createPipeline", {
      companyId,
      pipelineData,
    });
    const result = await collections.pipelines.insertOne({
      ...pipelineData,
      createdDate: pipelineData.createdDate
        ? new Date(pipelineData.createdDate)
        : new Date(),
    });
    console.log("[PipelineService] insertOne result", { result });
    if (result.insertedId) {
      const inserted = await collections.pipelines.findOne({
        _id: result.insertedId,
      });
      console.log("[PipelineService] inserted pipeline", { inserted });
      return { done: true, data: inserted };
    } else {
      console.error("[PipelineService] Failed to insert pipeline");
      return { done: false, error: "Failed to insert pipeline" };
    }
  } catch (error) {
    console.error("[PipelineService] Error in createPipeline", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

export const getPipelines = async (companyId, filters = {}) => {
  try {
    const collections = getTenantCollections(companyId);
    console.log("[PipelineService] getPipelines", { companyId });
    const query = { companyId };

    // Sort by createdDate descending (most recent first)
    const sort = { createdDate: -1 };

    console.log("[PipelineService] Final query", { query, sort });
    const pipelines = await collections.pipelines
      .find(query)
      .sort(sort)
      .toArray();
    console.log("[PipelineService] found pipelines", {
      count: pipelines.length,
    });

    // Ensure dates are properly converted to Date objects
    const processedPipelines = pipelines.map((pipeline) => ({
      ...pipeline,
      createdDate: pipeline.createdDate ? new Date(pipeline.createdDate) : null,
    }));

    // Debug: Log first few pipelines to see date format
    if (processedPipelines.length > 0) {
      console.log(
        "[PipelineService] Sample pipeline dates after processing:",
        processedPipelines.slice(0, 3).map((p) => ({
          id: p._id,
          createdDate: p.createdDate,
          createdDateType: typeof p.createdDate,
          createdDateConstructor: p.createdDate?.constructor?.name,
          createdDateISO: p.createdDate
            ? p.createdDate instanceof Date
              ? p.createdDate.toISOString()
              : "Not a Date object"
            : null,
        }))
      );
    }

    return { done: true, data: processedPipelines };
  } catch (error) {
    console.error("[PipelineService] Error in getPipelines", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

export const updatePipeline = async (companyId, pipelineId, updateData) => {
  try {
    const collections = getTenantCollections(companyId);
    console.log("[PipelineService] updatePipeline", {
      companyId,
      pipelineId,
      updateData,
    });

    // Validate ObjectId format
    if (!ObjectId.isValid(pipelineId)) {
      console.error("[PipelineService] Invalid ObjectId format", {
        pipelineId,
      });
      return { done: false, error: "Invalid pipeline ID format" };
    }

    // First check if pipeline exists and log its details
    const existingPipeline = await collections.pipelines.findOne({
      _id: new ObjectId(pipelineId),
    });
    console.log("[PipelineService] existing pipeline found", {
      existingPipeline,
    });

    if (!existingPipeline) {
      console.error("[PipelineService] Pipeline not found", { pipelineId });
      return { done: false, error: "Pipeline not found" };
    }

    // Log the pipeline's companyId if it exists
    if (existingPipeline.companyId) {
      console.log("[PipelineService] Pipeline companyId", {
        pipelineCompanyId: existingPipeline.companyId,
        requestCompanyId: companyId,
        match: existingPipeline.companyId === companyId,
      });
    } else {
      console.log("[PipelineService] Pipeline has no companyId field");
    }

    // Update the pipeline
    const result = await collections.pipelines.updateOne(
      { _id: new ObjectId(pipelineId) },
      { $set: updateData }
    );

    console.log("[PipelineService] update result", { result });

    if (result.matchedCount === 0) {
      console.error("[PipelineService] Pipeline not found for update", {
        pipelineId,
      });
      return { done: false, error: "Pipeline not found" };
    }

    // Get the updated pipeline
    const updatedPipeline = await collections.pipelines.findOne({
      _id: new ObjectId(pipelineId),
    });
    console.log("[PipelineService] updated pipeline", { updatedPipeline });

    return { done: true, data: updatedPipeline };
  } catch (error) {
    console.error("[PipelineService] Error in updatePipeline", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

export const deletePipeline = async (companyId, pipelineId) => {
  try {
    const collections = getTenantCollections(companyId);
    console.log("[PipelineService] deletePipeline", { companyId, pipelineId });

    // Validate ObjectId format
    if (!ObjectId.isValid(pipelineId)) {
      console.error("[PipelineService] Invalid ObjectId format", {
        pipelineId,
      });
      return { done: false, error: "Invalid pipeline ID format" };
    }

    // First check if pipeline exists
    const existingPipeline = await collections.pipelines.findOne({
      _id: new ObjectId(pipelineId),
    });
    if (!existingPipeline) {
      console.error("[PipelineService] Pipeline not found for delete", {
        pipelineId,
      });
      return { done: false, error: "Pipeline not found" };
    }

    // Delete the pipeline
    const result = await collections.pipelines.deleteOne({
      _id: new ObjectId(pipelineId),
    });
    console.log("[PipelineService] delete result", { result });

    if (result.deletedCount === 0) {
      console.error("[PipelineService] Pipeline not found for delete", {
        pipelineId,
      });
      return { done: false, error: "Pipeline not found" };
    }

    return { done: true, data: existingPipeline };
  } catch (error) {
    console.error("[PipelineService] Error in deletePipeline", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

// Export pipeline data as PDF
export const exportPipelinesPDF = async (companyId) => {
  try {
    console.log("Starting PDF generation for pipelines:", companyId);

    if (!companyId) {
      throw new Error("Company ID is required");
    }

    const collections = getTenantCollections(companyId);

    if (!collections || !collections.pipelines) {
      throw new Error("Pipeline collection not found for company");
    }

    // Fetch all pipelines for the company
    const pipelines = await collections.pipelines.find({}).toArray();

    if (!pipelines || pipelines.length === 0) {
      throw new Error("No pipelines found for export");
    }

    // Debug: Log the first pipeline to see the date format
    if (pipelines.length > 0) {
      console.log("PDF Export - First pipeline data:", {
        pipelineName: pipelines[0].pipelineName,
        createdAt: pipelines[0].createdAt,
        updatedAt: pipelines[0].updatedAt,
        createdAtType: typeof pipelines[0].createdAt,
        updatedAtType: typeof pipelines[0].updatedAt,
      });
    }

    // Create PDF document
    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
      bufferPages: true,
    });

    const fileName = `pipelines_${companyId}_${Date.now()}.pdf`;
    const tempDir = path.join(process.cwd(), "temp");
    const filePath = path.join(tempDir, fileName);

    // Create write stream
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    // Set up fonts and colors
    const primaryColor = "#333333";
    const secondaryColor = "#666666";
    const accentColor = "#0d6efd";
    const pageWidth = doc.page.width - 100;

    // Add header
    doc
      .fontSize(24)
      .font("Helvetica-Bold")
      .fillColor(primaryColor)
      .text("Pipeline Report", 50, 50)
      .moveDown(0.5);

    // Add report details
    doc
      .fontSize(12)
      .font("Helvetica")
      .fillColor(secondaryColor)
      .text(`Generated on: ${format(new Date(), "dd/MM/yyyy HH:mm")}`, {
        align: "right",
      })
      .text(`Total Pipelines: ${pipelines.length}`, { align: "right" })
      .moveDown(2);

    // Table header
    const tableTop = 150;
    const columnWidth = pageWidth / 6;

    // Draw table header background
    doc
      .rect(50, tableTop - 10, pageWidth, 30)
      .fillColor("#f8f9fa")
      .fill();

    // Table headers (only the required fields)
    doc
      .fontSize(10)
      .font("Helvetica-Bold")
      .fillColor(primaryColor)
      .text("Pipeline Name", 50, tableTop, { width: columnWidth })
      .text("Total Deal Value", 50 + columnWidth, tableTop, {
        width: columnWidth,
      })
      .text("No. of Deals", 50 + columnWidth * 2, tableTop, {
        width: columnWidth,
      })
      .text("Stage", 50 + columnWidth * 3, tableTop, { width: columnWidth })
      .text("Status", 50 + columnWidth * 4, tableTop, { width: columnWidth })
      .text("Created Date", 50 + columnWidth * 5, tableTop, {
        width: columnWidth,
      });

    // Table content (only the required fields)
    let currentY = tableTop + 20;
    pipelines.forEach((pipeline, index) => {
      // Check if we need a new page
      if (currentY > doc.page.height - 100) {
        doc.addPage();
        currentY = 50;
      }

      // Helper function to safely format dates
      const formatDate = (dateValue) => {
        try {
          if (!dateValue) return "N/A";
          const date = new Date(dateValue);
          if (isNaN(date.getTime())) return "N/A";
          return format(date, "dd/MM/yyyy");
        } catch (error) {
          console.warn("Date formatting error:", error);
          return "N/A";
        }
      };

      doc
        .fontSize(9)
        .font("Helvetica")
        .fillColor(secondaryColor)
        .text(pipeline.pipelineName || "N/A", 50, currentY, {
          width: columnWidth,
        })
        .text(
          pipeline.totalDealValue != null
            ? `$${pipeline.totalDealValue}`
            : "N/A",
          50 + columnWidth,
          currentY,
          { width: columnWidth }
        )
        .text(
          pipeline.noOfDeals != null ? pipeline.noOfDeals.toString() : "N/A",
          50 + columnWidth * 2,
          currentY,
          { width: columnWidth }
        )
        .text(pipeline.stage || "N/A", 50 + columnWidth * 3, currentY, {
          width: columnWidth,
        })
        .text(pipeline.status || "N/A", 50 + columnWidth * 4, currentY, {
          width: columnWidth,
        })
        .text(
          formatDate(pipeline.createdDate),
          50 + columnWidth * 5,
          currentY,
          { width: columnWidth }
        );

      currentY += 20;
    });

    // Add page numbers
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);

      doc
        .fontSize(10)
        .font("Helvetica")
        .fillColor("#999999")
        .text(`Page ${i + 1} of ${pages.count}`, 50, doc.page.height - 30, {
          align: "center",
        });
    }

    // Finalize PDF
    doc.end();

    // Wait for stream to finish
    await new Promise((resolve, reject) => {
      stream.on("finish", () => {
        console.log("PDF file written successfully");
        resolve();
      });
      stream.on("error", (err) => {
        console.error("Error writing PDF file:", err);
        reject(err);
      });
    });

    // Verify file exists
    if (!fs.existsSync(filePath)) {
      throw new Error("PDF file was not created");
    }

    console.log("PDF generation completed successfully");
    const frontendurl = process.env.FRONTEND_URL + `/temp/${fileName}`;

    return {
      done: true,
      data: {
        pdfPath: filePath,
        pdfUrl: frontendurl,
      },
    };
  } catch (error) {
    console.error("Error generating PDF:", error);
    return { done: false, error: error.message };
  }
};

// Export pipeline data as Excel
export const exportPipelinesExcel = async (companyId) => {
  try {
    console.log("Starting Excel generation for pipelines:", companyId);

    if (!companyId) {
      throw new Error("Company ID is required");
    }

    const collections = getTenantCollections(companyId);

    if (!collections || !collections.pipelines) {
      throw new Error("Pipeline collection not found for company");
    }

    // Fetch all pipelines for the company
    const pipelines = await collections.pipelines.find({}).toArray();

    if (!pipelines || pipelines.length === 0) {
      throw new Error("No pipelines found for export");
    }

    // Debug: Log the first pipeline to see the date format
    if (pipelines.length > 0) {
      console.log("Excel Export - First pipeline data:", {
        pipelineName: pipelines[0].pipelineName,
        createdAt: pipelines[0].createdAt,
        updatedAt: pipelines[0].updatedAt,
        createdAtType: typeof pipelines[0].createdAt,
        updatedAtType: typeof pipelines[0].updatedAt,
      });
    }

    // Create workbook and worksheet
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Pipelines");

    // Define columns (only the required fields)
    worksheet.columns = [
      { header: "Pipeline Name", key: "pipelineName", width: 30 },
      { header: "Total Deal Value", key: "totalDealValue", width: 15 },
      { header: "No. of Deals", key: "noOfDeals", width: 15 },
      { header: "Stage", key: "stage", width: 15 },
      { header: "Status", key: "status", width: 15 },
      { header: "Created Date", key: "createdDate", width: 15 },
    ];

    // Style the header row
    worksheet.getRow(1).font = { bold: true };
    worksheet.getRow(1).fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FFE0E0E0" },
    };

    // Helper function to safely format dates
    const formatDate = (dateValue) => {
      try {
        if (!dateValue) return "N/A";
        const date = new Date(dateValue);
        if (isNaN(date.getTime())) return "N/A";
        return format(date, "dd/MM/yyyy");
      } catch (error) {
        console.warn("Date formatting error:", error);
        return "N/A";
      }
    };

    // Add data rows (only the required fields)
    pipelines.forEach((pipeline) => {
      worksheet.addRow({
        pipelineName: pipeline.pipelineName || "N/A",
        totalDealValue:
          pipeline.totalDealValue != null ? pipeline.totalDealValue : "N/A",
        noOfDeals: pipeline.noOfDeals != null ? pipeline.noOfDeals : "N/A",
        stage: pipeline.stage || "N/A",
        status: pipeline.status || "N/A",
        createdDate: formatDate(pipeline.createdDate),
      });
    });

    // Add summary row
    const totalRow = worksheet.addRow({
      pipelineName: "TOTAL",
      totalDealValue: pipelines.reduce(
        (sum, p) => sum + (p.totalDealValue || 0),
        0
      ),
      noOfDeals: pipelines.reduce((sum, p) => sum + (p.noOfDeals || 0), 0),
      stage: "",
      status: "",
      createdDate: "",
    });
    totalRow.font = { bold: true };
    totalRow.fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FFF0F0F0" },
    };

    // Generate file
    const fileName = `pipelines_${companyId}_${Date.now()}.xlsx`;
    const tempDir = path.join(process.cwd(), "temp");
    const filePath = path.join(tempDir, fileName);

    await workbook.xlsx.writeFile(filePath);

    console.log("Excel generation completed successfully");
    const frontendurl = process.env.FRONTEND_URL + `/temp/${fileName}`;

    return {
      done: true,
      data: {
        excelPath: filePath,
        excelUrl: frontendurl,
      },
    };
  } catch (error) {
    console.error("Error generating Excel:", error);
    return { done: false, error: error.message };
  }
};

// --- Stage Management ---
export const getStages = async (companyId) => {
  try {
    console.log("[StageService] getStages called with companyId:", companyId);
    const collections = getTenantCollections(companyId);
    console.log("[StageService] Using database for companyId:", companyId);
    const stages = await collections.stages.find({ companyId }).toArray();
    console.log(
      "[StageService] Found stages:",
      stages.length,
      "for companyId:",
      companyId
    );
    return { done: true, data: stages };
  } catch (error) {
    console.error("[StageService] Error in getStages", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

export const addStage = async (companyId, name) => {
  try {
    console.log(
      "[StageService] addStage called with companyId:",
      companyId,
      "name:",
      name
    );
    const collections = getTenantCollections(companyId);
    console.log("[StageService] Using database for companyId:", companyId);
    // Prevent duplicate stage names for the same company
    const existing = await collections.stages.findOne({ name, companyId });
    if (existing) {
      return { done: false, error: "Stage already exists" };
    }
    const result = await collections.stages.insertOne({ name, companyId });
    console.log("[StageService] Stage inserted with result:", result);
    if (result.insertedId) {
      const stages = await collections.stages.find({ companyId }).toArray();
      console.log("[StageService] Total stages after adding:", stages.length);
      return { done: true, data: stages };
    } else {
      return { done: false, error: "Failed to add stage" };
    }
  } catch (error) {
    console.error("[StageService] Error in addStage", { error: error.message });
    return { done: false, error: error.message };
  }
};

export const updateStage = async (companyId, stageId, newName) => {
  try {
    const collections = getTenantCollections(companyId);
    // Only allow update for this company's stage
    const result = await collections.stages.updateOne(
      { _id: new ObjectId(stageId), companyId },
      { $set: { name: newName } }
    );
    if (result.modifiedCount === 1) {
      const stages = await collections.stages.find({ companyId }).toArray();
      return { done: true, data: stages };
    } else {
      return { done: false, error: "Stage not found or not updated" };
    }
  } catch (error) {
    console.error("[StageService] Error in updateStage", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};

export const overwriteStages = async (companyId, stages) => {
  try {
    const collections = getTenantCollections(companyId);

    // Get current stages before deletion to identify which ones are being removed
    const currentStages = await collections.stages
      .find({ companyId })
      .toArray();
    const currentStageNames = currentStages.map((s) => s.name);
    const newStageNames = Array.isArray(stages) ? stages : [];

    // Find stages that are being deleted
    const deletedStageNames = currentStageNames.filter(
      (stageName) => !newStageNames.includes(stageName)
    );

    console.log(
      "[StageService] overwriteStages - Current stages:",
      currentStageNames
    );
    console.log("[StageService] overwriteStages - New stages:", newStageNames);
    console.log(
      "[StageService] overwriteStages - Stages being deleted:",
      deletedStageNames
    );

    // Remove all existing stages for this company
    await collections.stages.deleteMany({ companyId });

    // Insert the new list
    if (Array.isArray(stages) && stages.length > 0) {
      await collections.stages.insertMany(
        stages.map((name) => ({ name, companyId }))
      );
    }

    let updatedPipelinesCount = 0;
    let defaultStage = "";

    // Update pipelines that use deleted stages
    if (deletedStageNames.length > 0 && newStageNames.length > 0) {
      defaultStage = newStageNames[0]; // Use first stage as default
      console.log(
        "[StageService] overwriteStages - Updating pipelines to use default stage:",
        defaultStage
      );

      // Find and update pipelines that use any of the deleted stages
      const updateResult = await collections.pipelines.updateMany(
        {
          companyId,
          stage: { $in: deletedStageNames },
        },
        {
          $set: { stage: defaultStage },
        }
      );

      updatedPipelinesCount = updateResult.modifiedCount;
      console.log(
        "[StageService] overwriteStages - Updated pipelines:",
        updatedPipelinesCount
      );
    }

    const updated = await collections.stages.find({ companyId }).toArray();
    return {
      done: true,
      data: updated,
      updatedPipelinesCount,
      defaultStage,
      deletedStages: deletedStageNames,
    };
  } catch (error) {
    console.error("[StageService] Error in overwriteStages", {
      error: error.message,
    });
    return { done: false, error: error.message };
  }
};
