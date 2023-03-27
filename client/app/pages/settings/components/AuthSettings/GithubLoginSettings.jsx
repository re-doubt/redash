import { isEmpty, join } from "lodash";
import React from "react";
import Form from "antd/lib/form";
import Select from "antd/lib/select";
import Alert from "antd/lib/alert";
import DynamicComponent from "@/components/DynamicComponent";
import { clientConfig } from "@/services/auth";
import { SettingsEditorPropTypes, SettingsEditorDefaultProps } from "../prop-types";

export default function GithubLoginSettings(props) {
  const { values, onChange } = props;

  if (!clientConfig.githubLoginEnabled) {
    return null;
  }

  return (
    <DynamicComponent name="OrganizationSettings.GithubLoginSettings" {...props}>
      <h4>Github Login</h4>
      <Form.Item label="Allowed GitHub Apps Domains">
        <Select
          mode="tags"
          value={values.auth_github_apps_domains}
          onChange={value => onChange({auth_github_apps_domains: value})}
        />
        {!isEmpty(values.auth_github_apps_domains) && (
          <Alert
            message={
              <p>
                Any user registered with a <strong>{join(values.auth_github_apps_domains, ", ")}</strong> GitHub
                account will be able to login. If they don{"'"}t have an existing user, a new user will be created and
                join the <strong>Default</strong> group.
              </p>
            }
            className="m-t-15"
          />
        )}
      </Form.Item>
    </DynamicComponent>
  );
}

GithubLoginSettings.propTypes = SettingsEditorPropTypes;

GithubLoginSettings.defaultProps = SettingsEditorDefaultProps;
