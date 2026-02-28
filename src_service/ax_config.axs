// ============================================================
//  StealthPalace Service Extender — ax_config.axs
// ============================================================

var metadata = {
    name: "StealthPalace",
    description: "StealthPalace RDLL loader - directory browser & agent compiler"
};

// Global variables
var g_output_widget = null;
var g_settings = {};

function InitService() {
    ax.log("StealthPalace service loaded.");

    ax.service_command("stealthpalace", "load_settings", null);

    let action_compile = menu.create_action("StealthPalace - Compile Agent", function () {
        buildCompileWindow();
    });
    menu.add_main_axscript(action_compile);
}

function handleLoad(response) {
    if (response.success) {
        try {
            g_settings = JSON.parse(response.output || "{}");
            ax.log("StealthPalace settings synchronized.");
        } catch(e) {
            ax.log("Error parsing settings: " + e);
        }
        return;
    } 
    ax.log("Failed to load settings: " + (response.error || "unknown error"));
}

function handleLogging(response) {
    if (g_output_widget !== null) {
        let currentText = g_output_widget.text();
        let msg = response.success ? response.output : ("Error: " + (response.error || "unknown"));
        g_output_widget.setText(currentText + msg + "\n");
    }
}

function data_handler(data) {
    let response = JSON.parse(data);

    switch (response.action) {
        case "load_settings_result":
            handleLoad(response);
            break;
        case "save_settings_log":
            handleLogging(response);
            break;
        case "load_settings_log":
            handleLogging(response);
            break;
        case "compile_log":
            handleLogging(response);
            break;
        default:
            ax.log("Unknown command from service: " + response.command);
    }
}

function buildCompileWindow() {
    ax.log("Opening Compile Agent window...");

    
    // Group 1: Input
    let fileSelectorDll = form.create_selector_file();
    fileSelectorDll.setPlaceholder("/path/to/agent.dll");

    let grid_input = form.create_gridlayout();
    grid_input.addWidget(form.create_label("Agent DLL (required):"), 0, 0, 1, 1);
    grid_input.addWidget(fileSelectorDll, 0, 1, 1, 1);
    let grp_input = form.create_groupbox("Input", false);
    let panel_input = form.create_panel();
    panel_input.setLayout(grid_input);
    grp_input.setPanel(panel_input);

    // Group 2: Build Options
    let comboFormat = form.create_combo();
    let formatItems = ["Exe", "Dll", "Bin", "Svc"];
    comboFormat.addItems(formatItems);

    let txt_out = form.create_textline();
    txt_out.setText("agent");

    let grid_build = form.create_gridlayout();
    grid_build.addWidget(form.create_label("Output Format:"), 0, 0, 1, 1);
    grid_build.addWidget(comboFormat, 0, 1, 1, 1);
    grid_build.addWidget(form.create_label("Output Name:"), 1, 0, 1, 1);
    grid_build.addWidget(txt_out, 1, 1, 1, 1);
    let grp_build = form.create_groupbox("Build Options", false);
    let panel_build = form.create_panel();
    panel_build.setLayout(grid_build);
    grp_build.setPanel(panel_build);

    // Group 3: Flags
    let chk_debug     = form.create_check("Debug (-mconsole)");
    let chk_skip_coff = form.create_check("Skip COFF (reuse .o)");
    let chk_skip_link = form.create_check("Skip Link (reuse agent.bin)");

    let grid_flags = form.create_gridlayout();
    grid_flags.addWidget(chk_debug, 0, 0, 1, 1);
    grid_flags.addWidget(chk_skip_coff, 1, 0, 1, 1);
    grid_flags.addWidget(chk_skip_link, 2, 0, 1, 1);
    let grp_flags = form.create_groupbox("Compiler Flags", false);
    let panel_flags = form.create_panel();
    panel_flags.setLayout(grid_flags);
    grp_flags.setPanel(panel_flags);

    // Group 4: Stomp
    let textlineHostDll = form.create_textline();
    let textlineStompDll = form.create_textline();
    let grid_stomp = form.create_gridlayout();
    grid_stomp.addWidget(form.create_label("Host DLL:"), 0, 0, 1, 1);
    grid_stomp.addWidget(textlineHostDll, 0, 1, 1, 1);
    grid_stomp.addWidget(form.create_label("Stomp DLL:"), 1, 0, 1, 1);
    grid_stomp.addWidget(textlineStompDll, 1, 1, 1, 1);
    let panel_stomp = form.create_panel();
    panel_stomp.setLayout(grid_stomp);
    let grp_stomp = form.create_groupbox("Stomp Options (optional)", true);
    grp_stomp.setPanel(panel_stomp);

    // Group 5: Output
    let txt_output = form.create_textmulti();
    txt_output.setReadOnly(true);
    g_output_widget = txt_output;
    let grp_output = form.create_groupbox("Output", false);
    let panel_output = form.create_panel();
    let grid_output = form.create_gridlayout();
    grid_output.addWidget(txt_output, 0, 0, 1, 1);
    panel_output.setLayout(grid_output);
    grp_output.setPanel(panel_output);


    if (g_settings.format) {
        let idx = formatItems.findIndex(i => i.toLowerCase() === g_settings.format.toLowerCase());
        if (idx !== -1) comboFormat.setCurrentIndex(idx);
    }
    if (g_settings.out) txt_out.setText(g_settings.out);
    if (g_settings.debug) chk_debug.setChecked(true);
    if (g_settings.skip_coff) chk_skip_coff.setChecked(true);
    if (g_settings.skip_link) chk_skip_link.setChecked(true);
    
    if (g_settings.host_dll || g_settings.stomp_dll) {
        grp_stomp.setChecked(true);
        panel_stomp.setEnabled(true);
        textlineHostDll.setText(g_settings.host_dll || "");
        textlineStompDll.setText(g_settings.stomp_dll || "");
    } else {
        grp_stomp.setChecked(false);
        panel_stomp.setEnabled(false);
    }

    let btn_save = form.create_button("Save Settings");
    let btn_compile = form.create_button("▶ Compile");

    form.connect(grp_stomp, "clicked", function (checked) {
        panel_stomp.setEnabled(checked);
    });

    form.connect(comboFormat, "currentTextChanged", function (text) {
        chk_skip_link.setEnabled(text.toLowerCase() !== "bin");
    });

    form.connect(btn_save, "clicked", function () {
        g_settings = {
            format: comboFormat.currentText(),
            out: txt_out.text(),
            pic: txt_out.text() + ".bin",
            debug: chk_debug.isChecked(),
            skip_coff: chk_skip_coff.isChecked(),
            skip_link: chk_skip_link.isChecked(),
            host_dll: textlineHostDll.text(),
            stomp_dll: textlineStompDll.text()
        };
        ax.service_command("stealthpalace", "save_settings", g_settings);
        ax.log("Settings cached and saved to service.");
    });

    form.connect(btn_compile, "clicked", function () {
        txt_output.setText("");
        let container = form.create_container();
        container.put("dll_content", fileSelectorDll);

        if (!container.get("dll_content")) {
            txt_output.setText("Please specify the agent DLL.");
            return;
        }

        ax.service_command("stealthpalace", "run_compile", {
            dll: container.toJson(),
            format: comboFormat.currentText(),
            out: txt_out.text(),
            pic: txt_out.text() + ".bin",
            debug: chk_debug.isChecked(),
            skip_coff: chk_skip_coff.isChecked(),
            skip_link: chk_skip_link.isChecked(),
            host_dll: grp_stomp.isChecked() ? textlineHostDll.text() : "",
            stomp_dll: grp_stomp.isChecked() ? textlineStompDll.text() : ""
        });
    });

    let main_layout = form.create_vlayout();
    main_layout.addWidget(grp_input);
    main_layout.addWidget(grp_build);
    main_layout.addWidget(grp_flags);
    main_layout.addWidget(grp_stomp);
    main_layout.addWidget(btn_save);
    main_layout.addWidget(btn_compile);
    main_layout.addWidget(grp_output);

    let dialog = form.create_dialog("StealthPalace — Compile Agent");
    dialog.setSize(620, 760);
    dialog.setLayout(main_layout);
    dialog.exec(); 

    g_output_widget = null;
}